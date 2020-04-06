package org.vaadin.artur.cors;

import java.lang.reflect.Proxy;
import java.util.Map;

import javax.servlet.ServletResponse;

import io.undertow.server.handlers.Cookie;
import io.undertow.servlet.spec.HttpServletResponseImpl;

public class UndertowCookieSupport {

    public static void handleSessionCookie(ServletResponse response) {
        if (!response.getClass().getName().equals("io.undertow.servlet.spec.HttpServletResponseImpl")) {
            return;
        }

        CorsFilter.debug("Undertow: running on Undertow");
        HttpServletResponseImpl resp = (HttpServletResponseImpl) response;
        resp.getExchange().addResponseCommitListener(serverExchange -> {
            for (Map.Entry<String, Cookie> responseCookie : serverExchange.getResponseCookies().entrySet()) {
                if (responseCookie.getKey().equals("JSESSIONID")) {
                    CorsFilter.debug("Undertow: Fixing session cookie");
                    serverExchange.getResponseCookies().replace(responseCookie.getKey(),
                            proxyCookie(responseCookie.getValue()));
                }
            }
        });
    }

    private static Cookie proxyCookie(Cookie cookie) {
        return (Cookie) Proxy.newProxyInstance(cookie.getClass().getClassLoader(), cookie.getClass().getInterfaces(),
                (proxy, method, args) -> {
                    if ("isSecure".equals(method.getName())) {
                        return true;
                    }
                    if ("isSameSite".equals(method.getName())) {
                        return true;
                    }
                    if ("getSameSiteMode".equals(method.getName())) {
                        return "None";
                    }
                    return method.invoke(cookie, args);
                });
    }

}