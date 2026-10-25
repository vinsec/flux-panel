package com.admin.config;

import com.admin.common.utils.WebSocketServer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.annotation.Resource;


@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    @Resource
    private WebSocketInterceptor webSocketInterceptor;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry webSocketHandlerRegistry) {
        webSocketHandlerRegistry
                .addHandler(myHandler(), "/system-info")
                .setAllowedOrigins("*")
                .addInterceptors(webSocketInterceptor);
    }


    @Bean
    public WebSocketHandler myHandler() {
        return new WebSocketServer();
    }

    @Bean
    public org.springframework.web.socket.server.standard.ServletServerContainerFactoryBean webSocketContainer(){
        var container=new org.springframework.web.socket.server.standard.ServletServerContainerFactoryBean();
        container.setMaxTextMessageBufferSize(16*1024*1024);
        container.setMaxBinaryMessageBufferSize(16*1024*1024);
        return container;
    }
}
