/**
 * web_server.c — HTTP + WebSocket Terminal + OTA
 *
 * Architektur:
 *   - ESP-IDF httpd (eingebaut, kein extra-Component nötig)
 *   - WebSocket: httpd nativ (ESP-IDF >= 4.4)
 *   - OTA: esp_ota_ops (HTTP POST, chunked write)
 *   - Terminal-UI: einzelne HTML-Seite, inline als C-String
 *   - LIN-Frames: aus ring_buffer lesen, per WS pushen
 *   - Befehle: per WS empfangen, an parse_command() weiterleiten
 */

#include "web_server.h"
#include "ring_buffer.h"
#include "lin_uart.h"
#include "version.h"

#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "WEB_SERVER";
static httpd_handle_t s_server = NULL;

// ── Forward-Deklaration (in lin_sniffer_main.c definiert) ────────
extern void parse_command(char *cmd, int sock);

// ── WebSocket Client (nur einer gleichzeitig erlaubt) ────────────
static struct {
    int              fd;
    ringbuf_reader_t reader;
} s_ws_client = { .fd = -1 };

static SemaphoreHandle_t s_ws_mutex = NULL;


// ── Terminal HTML ─────────────────────────────────────────────────

static const char TERMINAL_HTML[] =
"<!DOCTYPE html><html lang='de'><head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>LIN Sniffer</title>"
"<style>"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{background:#1a1a1a;color:#d4d4d4;font:13px/1.4 'Cascadia Code','Fira Code',monospace;display:flex;flex-direction:column;position:fixed;top:0;left:0;right:0;bottom:0;overflow:hidden}"
"#header{background:#252526;padding:8px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #333}"
"#header h1{font-size:14px;font-weight:600;color:#fff}"
"#status{width:8px;height:8px;border-radius:50%;background:#f44}"
"#status.ok{background:#4caf50}"
"#version{margin-left:auto;color:#666;font-size:11px}"
"#log{flex:1;overflow-y:auto;padding:8px 12px;font-size:12px;white-space:pre}"
".rx{color:#9cdcfe}.tx{color:#dcdcaa}.err{color:#f44747}.info{color:#6a9955}.sys{color:#c586c0}"
"#inputbar{display:flex;gap:6px;padding:8px;background:#252526;border-top:1px solid #333}"
"#cmd{flex:1;background:#3c3c3c;border:1px solid #555;color:#d4d4d4;padding:6px 10px;font:inherit;border-radius:3px;outline:none}"
"#cmd:focus{border-color:#007acc}"
"button{background:#007acc;color:#fff;border:none;padding:6px 14px;border-radius:3px;cursor:pointer;font:inherit}"
"button:hover{background:#1a8ad4}"
"button:active{transform:scale(0.95);opacity:0.8}"
"@keyframes pole{0%{background-position:0 0}100%{background-position:40px 0}}"
"#otafill{height:100%;width:0%;background:#4caf50;transition:width .3s ease}"
"#otafill.indeterminate{"
"  width:100%!important;"
"  background:repeating-linear-gradient(90deg,#4caf50 0,#4caf50 20px,#66bb6a 20px,#66bb6a 40px);"
"  background-size:40px 100%;"
"  animation:pole .5s linear infinite"
"}"
"</style></head><body>"
"<div id='header'>"
"  <div id='status'></div>"
"  <h1>LIN Sniffer</h1>"
"  <button id='connbtn' onclick='toggleConn()' style='background:#4caf50;font-size:11px;padding:4px 10px'>Connect</button>"
"  <span id='ip' style='color:#888;font-size:11px'></span>"
"  <div style='margin-left:auto;display:flex;gap:6px;align-items:center'>"
"    <input id='otafile' type='file' accept='.bin' style='display:none' />"
"    <button onclick='document.getElementById(\"otafile\").click()' style='background:#5a3e8a;padding:4px 10px;font-size:11px'>Flash</button>"
"    <div id='otaprog' style='display:none;width:150px;height:6px;background:#333;border-radius:3px;overflow:hidden'>"
"      <div id='otafill' style='height:100%;width:0%;background:#4caf50;transition:width .3s ease'></div>"
"    </div>"
"    <span id='otastatus' style='color:#888;font-size:10px;min-width:100px'></span>"
"  </div>"
"</div>"
"<div id='log'></div>"
"<div id='inputbar'>"
"  <input id='cmd' type='text' placeholder='Command (e.g. HEADER 0E, SCAN, HELP)' autocomplete='off' spellcheck='false' autofocus />"
"  <button onclick='sendCmd()'>Send</button>"
"  <button onclick='clearLog()' style='background:#444'>Clear</button>"
"  <button onclick='copyLog()' style='background:#444'>Copy</button>"
"</div>"
"<script>"
"const log=document.getElementById('log');"
"const status=document.getElementById('status');"
"let ws,autoScroll=true;"
"const connbtn=document.getElementById('connbtn');"
""
"function appendLine(text,cls){"
"  const el=document.createElement('div');"
"  el.className=cls||'';"
"  el.textContent=text.replace(/\\r\\n|\\n$/,'');"
"  log.appendChild(el);"
"  if(autoScroll)log.scrollTop=log.scrollHeight;"
"  while(log.children.length>2000)log.removeChild(log.firstChild);"
"}"
""
"function classForLine(l){"
"  if(l.includes('# RX'))return 'rx';"
"  if(l.includes('# TX')||l.includes('# SIM'))return 'tx';"
"  if(l.includes('UNANSWERED'))return 'err';"
"  if(l.includes('ERROR'))return 'err';"
"  if(l.startsWith('#'))return 'info';"
"  return 'sys';"
"}"
""
"function updBtn(on){"
"  connbtn.textContent=on?'Disconnect':'Connect';"
"  connbtn.style.background=on?'#f44336':'#4caf50';"
"}"
""
"function connect(){"
"  if(ws&&ws.readyState<2)return;"
"  const proto=location.protocol==='https:'?'wss':'ws';"
"  ws=new WebSocket(proto+'://'+location.host+'/ws');"
"  ws.onopen=()=>{"
"    if(pendingReload){"
"      pendingReload=false;"
"      location.replace(location.href.split('?')[0]+'?t='+Date.now());"
"      return;"
"    }"
"    status.className='ok';"
"    updBtn(true);"
"    document.getElementById('ip').textContent=location.host;"
"    appendLine('# Connected','info');"
"  };"
"  ws.onmessage=e=>{"
"    e.data.split('\\n').forEach(l=>{if(l.trim())appendLine(l,classForLine(l));});"
"  };"
"  ws.onclose=()=>{"
"    status.className='';"
"    updBtn(false);"
"    ws=null;"
"  };"
"  ws.onerror=()=>ws.close();"
"}"
""
"function disconnect(){"
"  if(ws){ws.close();ws=null;}"
"  status.className='';"
"  updBtn(false);"
"  appendLine('# Getrennt','err');"
"}"
""
"function toggleConn(){"
"  if(ws&&ws.readyState<2)disconnect();else connect();"
"}"
""
"function sendCmd(){"
"  const inp=document.getElementById('cmd');"
"  const v=inp.value.trim();"
"  if(!v||!ws||ws.readyState!==1)return;"
"  ws.send(v);"
"  appendLine('> '+v,'sys');"
"  if(!cmdHistory.length||cmdHistory[0]!==v)cmdHistory.unshift(v);"
"  if(cmdHistory.length>50)cmdHistory.length=50;"
"  historyPos=-1;"
"  historyDraft='';"
"  inp.value='';"
"}"
""
"document.getElementById('cmd').addEventListener('keydown',e=>{"
"  if(e.key==='Enter'){sendCmd();return;}"
"  if(e.key==='ArrowUp'){"
"    e.preventDefault();"
"    if(historyPos===-1)historyDraft=e.target.value;"
"    if(historyPos<cmdHistory.length-1){historyPos++;e.target.value=cmdHistory[historyPos];}"
"    return;"
"  }"
"  if(e.key==='ArrowDown'){"
"    e.preventDefault();"
"    if(historyPos>0){historyPos--;e.target.value=cmdHistory[historyPos];}"
"    else if(historyPos===0){historyPos=-1;e.target.value=historyDraft;}"
"    return;"
"  }"
"});"
""
"function clearLog(){log.innerHTML='';}"
""
"function copyLog(){"
"  const lines=Array.from(log.children).map(el=>el.textContent).join('\\n');"
"  if(navigator.clipboard&&navigator.clipboard.writeText){"
"    navigator.clipboard.writeText(lines).then(()=>{"
"      appendLine('# All output copied to clipboard','info');"
"    }).catch(err=>{"
"      appendLine('# Copy failed: '+err,'err');"
"    });"
"  }else{"
"    const ta=document.createElement('textarea');"
"    ta.value=lines;"
"    ta.style.position='fixed';ta.style.opacity='0';"
"    document.body.appendChild(ta);"
"    ta.select();"
"    try{"
"      document.execCommand('copy');"
"      appendLine('# All output copied to clipboard','info');"
"    }catch(err){"
"      appendLine('# Copy failed: '+err,'err');"
"    }"
"    document.body.removeChild(ta);"
"  }"
"}"
""
"log.addEventListener('scroll',()=>{"
"  autoScroll=log.scrollTop+log.clientHeight>=log.scrollHeight-20;"
"});"
""
"document.getElementById('otafile').addEventListener('change',startOta);"
""
"function startOta(){"
"  const f=document.getElementById('otafile').files[0];"
"  if(!f){alert('Please select .bin file');return;}"
"  const prog=document.getElementById('otaprog');"
"  const fill=document.getElementById('otafill');"
"  const st=document.getElementById('otastatus');"
""
"  prog.style.display='block';"
"  fill.style.width='0%';"
"  fill.classList.remove('indeterminate');"
"  st.textContent='Uploading...';"
""
"  const xhr=new XMLHttpRequest();"
""
"  xhr.upload.onprogress=function(e){"
"    if(e.lengthComputable){"
"      const pct=Math.round(e.loaded/e.total*100);"
"      fill.style.width=pct+'%';"
"      st.textContent='Uploading... '+pct+'%';"
"    }"
"  };"
""
"  xhr.upload.onload=function(){"
"    fill.classList.add('indeterminate');"
"    st.textContent='Flashing...';"
"    appendLine('# OTA: Upload complete, flashing...','info');"
"  };"
""
"  xhr.onload=function(){"
"    fill.classList.remove('indeterminate');"
"    fill.style.width='100%';"
"    if(xhr.status===200){"
"      st.textContent='OK - Rebooting...';"
"      appendLine('# OTA successful - waiting for reboot...','info');"
"      waitForReboot();"
"    }else{"
"      st.textContent='Error: '+xhr.status;"
"      appendLine('# OTA Error: '+xhr.status,'err');"
"    }"
"  };"
""
"  xhr.onerror=function(){"
"    fill.classList.remove('indeterminate');"
"    st.textContent='Upload failed';"
"    appendLine('# OTA Upload failed','err');"
"  };"
""
"  xhr.open('POST','/ota');"
"  xhr.setRequestHeader('Content-Type','application/octet-stream');"
"  xhr.send(f);"
"}"
""
"function waitForReboot(){"
"  pendingReload=true;"
"  const st=document.getElementById('otastatus');"
"  let attempts=0;"
"  const max=60;"
"  const timer=setInterval(()=>{"
"    attempts++;"
"    st.textContent='Waiting for reboot... ('+attempts+'s)';"
"    if(!pendingReload){"
"      clearInterval(timer);"
"      st.textContent='';"
"    }"
"    if(attempts>=max){"
"      clearInterval(timer);"
"      pendingReload=false;"
"      st.textContent='Timeout - please reload manually';"
"    }"
"  },1000);"
"}"
""
"(function autoConnect(){"
"  const t0=Date.now(),tmo=10000,iv=setInterval(()=>{"
"    if(ws&&ws.readyState===1){clearInterval(iv);return;}"
"    if(Date.now()-t0>tmo){clearInterval(iv);appendLine('# Auto-Connect Timeout — bitte manuell verbinden','err');return;}"
"    connect();"
"  },3000);"
"  connect();"
"})();"
"</script></body></html>";

// ── HTTP Handler: GET / ───────────────────────────────────────────

static esp_err_t handler_root(httpd_req_t *req)
{
    ESP_LOGI(TAG, "GET /");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    return httpd_resp_send(req, TERMINAL_HTML, strlen(TERMINAL_HTML));
}

// ── HTTP Handler: POST /ota ───────────────────────────────────────

static esp_err_t handler_ota(httpd_req_t *req)
{
    ESP_LOGI(TAG, "OTA Start, Content-Length: %d", req->content_len);

    const esp_partition_t *update_part =
        esp_ota_get_next_update_partition(NULL);

    if (!update_part) {
        ESP_LOGE(TAG, "No OTA partition found!");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "No OTA partition");
        return ESP_FAIL;
    }

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_part, OTA_WITH_SEQUENTIAL_WRITES,
                                  &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "OTA begin failed");
        return ESP_FAIL;
    }

    char *buf = malloc(4096);
    if (!buf) {
        esp_ota_abort(ota_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Out of memory");
        return ESP_FAIL;
    }

    int total     = 0;
    int remaining = req->content_len;

    while (remaining > 0) {
        int to_read  = (remaining < 4096) ? remaining : 4096;
        int received = httpd_req_recv(req, buf, to_read);

        if (received <= 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) continue;
            ESP_LOGE(TAG, "Receive error: %d", received);
            free(buf);
            esp_ota_abort(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                "Receive error");
            return ESP_FAIL;
        }

        err = esp_ota_write(ota_handle, buf, received);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write: %s", esp_err_to_name(err));
            free(buf);
            esp_ota_abort(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                "OTA write failed");
            return ESP_FAIL;
        }

        total     += received;
        remaining -= received;
        ESP_LOGD(TAG, "OTA: %d / %d bytes", total, req->content_len);
    }

    free(buf);

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "OTA end failed");
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_part);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Set boot partition failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA successful (%d bytes) — Reboot...", total);
    httpd_resp_sendstr(req, "OK");

    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

    return ESP_OK;
}

// ── WebSocket Handler: GET /ws ────────────────────────────────────

static void ws_client_add(int fd)
{
    xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    if (s_ws_client.fd != -1 && s_ws_client.fd != fd) {
        ESP_LOGI(TAG, "WS: new client fd=%d, kicking old fd=%d", fd, s_ws_client.fd);
        httpd_sess_trigger_close(s_server, s_ws_client.fd);
        s_ws_client.fd = -1;
    }
    s_ws_client.fd = fd;
    ringbuf_reader_init_from_history(&s_ws_client.reader, CONFIG_WS_RECONNECT_HISTORY_LINES);
    ESP_LOGI(TAG, "WS Client %d connected", fd);
    xSemaphoreGive(s_ws_mutex);
}

static void ws_client_remove(int fd)
{
    xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    if (s_ws_client.fd == fd) {
        s_ws_client.fd = -1;
        ESP_LOGI(TAG, "WS Client %d disconnected", fd);
    }
    xSemaphoreGive(s_ws_mutex);
}

static esp_err_t handler_ws(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);

    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "WS: Client connected fd=%d", fd);
        ws_client_add(fd);

        return ESP_OK;
    }

    // Daten-Frame empfangen
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(ws_pkt));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK || ws_pkt.len == 0) {
        ws_client_remove(fd);
        return ret;
    }

    uint8_t *buf = calloc(ws_pkt.len + 1, 1);
    if (!buf) return ESP_ERR_NO_MEM;

    ws_pkt.payload = buf;
    ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
        free(buf);
        ws_client_remove(fd);
        return ret;
    }

    parse_command((char *)buf, WS_FAKE_SOCK);

    free(buf);
    return ESP_OK;
}

// ── WS Push Task: Ring-Buffer → alle WS-Clients ──────────────────

static void ws_push_task(void *pvParameters)
{
    static char batch[4096];
    char msg[RINGBUF_ENTRY_SIZE];

    while (1) {
        bool any_sent = false;

        xSemaphoreTake(s_ws_mutex, portMAX_DELAY);

        if (s_ws_client.fd != -1) {
            size_t len       = 0;
            size_t batch_len = 0;

            while (ringbuf_read(&s_ws_client.reader, msg, &len)) {
                if (batch_len + len > sizeof(batch)) {
                    httpd_ws_frame_t pkt = {
                        .type    = HTTPD_WS_TYPE_TEXT,
                        .payload = (uint8_t *)batch,
                        .len     = batch_len,
                    };
                    esp_err_t err = httpd_ws_send_frame_async(
                        s_server, s_ws_client.fd, &pkt);
                    if (err != ESP_OK) {
                        ESP_LOGW(TAG, "WS send fd=%d failed, removing client",
                                 s_ws_client.fd);
                        s_ws_client.fd = -1;
                        batch_len = 0;
                        break;
                    }
                    any_sent  = true;
                    batch_len = 0;
                }
                memcpy(batch + batch_len, msg, len);
                batch_len += len;
            }

            if (s_ws_client.fd != -1 && batch_len > 0) {
                httpd_ws_frame_t pkt = {
                    .type    = HTTPD_WS_TYPE_TEXT,
                    .payload = (uint8_t *)batch,
                    .len     = batch_len,
                };
                esp_err_t err = httpd_ws_send_frame_async(
                    s_server, s_ws_client.fd, &pkt);
                if (err != ESP_OK) {
                    ESP_LOGW(TAG, "WS send fd=%d failed, removing client",
                             s_ws_client.fd);
                    s_ws_client.fd = -1;
                } else {
                    any_sent = true;
                }
            }
        }

        xSemaphoreGive(s_ws_mutex);

        vTaskDelay(pdMS_TO_TICKS(any_sent ? 10 : 20));
    }
}

// ── Server starten/stoppen ────────────────────────────────────────

void web_server_start(void)
{
    s_ws_mutex     = xSemaphoreCreateMutex();
    s_ws_client.fd = -1;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = 80;
    cfg.max_open_sockets = 4;
    cfg.lru_purge_enable = true;
    cfg.stack_size         = 8192;
    cfg.max_uri_handlers   = 8;
    cfg.recv_wait_timeout  = 10;
    cfg.send_wait_timeout  = 10;

    if (httpd_start(&s_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed");
        return;
    }

    static const httpd_uri_t uri_root = {
        .uri     = "/",
        .method  = HTTP_GET,
        .handler = handler_root,
    };
    httpd_register_uri_handler(s_server, &uri_root);

    static const httpd_uri_t uri_ota = {
        .uri     = "/ota",
        .method  = HTTP_POST,
        .handler = handler_ota,
    };
    httpd_register_uri_handler(s_server, &uri_ota);

    static const httpd_uri_t uri_ws = {
        .uri          = "/ws",
        .method       = HTTP_GET,
        .handler      = handler_ws,
        .is_websocket = true,
        .handle_ws_control_frames = false,
    };
    httpd_register_uri_handler(s_server, &uri_ws);

    xTaskCreate(ws_push_task, "ws_push", 4096, NULL, 4, NULL);

    ESP_LOGI(TAG, "Webserver v" LIN_SNIFFER_VERSION " started on port 80");
}

void web_server_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
}