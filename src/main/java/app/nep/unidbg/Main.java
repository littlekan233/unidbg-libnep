package app.nep.unidbg;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        // main entry
        log.info("libnep.so unidbg http server, 版本 v1.0");
        log.info("此项目仅供学习，请勿用于商业化用途！");

        // 初始化模拟器
        log.info("初始化模拟器...");
        EmulatorCore emucore = new EmulatorCore(getWorkingPath());

        // 启动http服务器
        log.info("正在启动http服务器...");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 20304), 64);
        ExecutorService workers = Executors.newFixedThreadPool(4);
        server.setExecutor(workers);

        server.createContext("/", exchange -> makeResponse(exchange, 200, "unidbg-libnep is running! "));
        server.createContext("/sign", exchange -> {
            // do sign
            try {
                // 获取待签名内容
                SignRequest info = new Gson().fromJson(
                        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                        SignRequest.class
                );
                SignRequest.SignHeaderRequest glHeaders = info.getGlHeader();

                // 将SignHeaderRequest改写为Map<String, String>，供签名方法使用。
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put("gl-clienttype", glHeaders.getClientType());
                headers.put("gl-deviceid", glHeaders.getDeviceId());
                headers.put("gl-nonce", glHeaders.getNonce());
                headers.put("gl-uid", glHeaders.getUid());
                headers.put("gl-token", glHeaders.getToken());

                String result;
                String reqtype = exchange.getRequestMethod().toUpperCase();
                synchronized (emucore) {
                    // GPT 5.6 Sol说这个不应该并发。
                    if (reqtype.equals("GET")) result = emucore.signGet(
                            info.getUrl(),
                            headers
                    ); // 签GET请求
                    else if (reqtype.equals("POST")) result = emucore.signPost(
                            info.getUrl(),
                            info.getBody(),
                            headers
                    ); // 签POST请求
                    else {
                        // 既不是GET又不是POST你让我签滚木？
                        makeResponse(exchange, 405, "invalid request method");
                        return;
                    }
                    // 签名成功，返回signed url
                    makeResponse(exchange, 200, result);
                }
            } catch (Throwable e) {
                // 签名怎么四了
                log.error("签名url失败！", e);
                makeResponse(exchange, 500, "url sign failed");
            }
        });

        // 监听Ctrl-C
        CountDownLatch stopped = new CountDownLatch(1);
        AtomicBoolean closing = new AtomicBoolean();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // shutdown hook
            if (!closing.compareAndSet(false, true)) return; // 正在关闭，跳过

            log.info("正在关闭http服务器...");
            server.stop(5);
            workers.shutdown();
            try {
                if (!workers.awaitTermination(5, TimeUnit.SECONDS)) {
                    log.warn("http服务器worker未在5秒内关闭！强制关闭中...");
                    workers.shutdownNow();
                }
                log.info("正在关闭模拟器...");
                emucore.destroy();
            } catch (Throwable e) {
                log.error("程序关闭时出现错误！", e);
            } finally {
                stopped.countDown();
                LogManager.shutdown();
            }
        }, "shutdown-hook"));

        // 启动！
        server.start();
        log.info("http服务器已在 127.0.0.1:20304 上运行！");
        stopped.await();
    }

    private static void makeResponse(HttpExchange exchange, int status, String content) throws IOException {
        // 构造响应
        byte[] data = Objects.toString(content, "").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, data.length);
        try (var out = exchange.getResponseBody()) {
            out.write(data);
        } finally {
            exchange.close();
        }
    }

    private static String getWorkingPath() {
        // 网上抄的。
        // source: https://blog.csdn.net/s_156/article/details/131548006
        // 下方注释为个人理解
        String path = Main.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .getPath();
        if (System.getProperty("os.name").contains("dows")){
            // Windows路径处理
            path = path.substring(1, path.length());
        }
        if (path.contains("jar")){
            // 是JAR文件
            path = path.substring(0, path.lastIndexOf("."));
            return path.substring(0, path.lastIndexOf("/"));
        }
        return path.replace("target/classes/", "");
    }

    @Data
    private static class SignRequest {
        // 签名请求格式
        private String url;
        private SignHeaderRequest glHeader;
        private String body;
        @Data
        static class SignHeaderRequest {
            // 签名请求格式 - 请求头
            private String clientType;
            private String deviceId;
            private String nonce;
            private String token;
            private String uid;
        }
    }
}
