/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.service84.services.authorization.configurations;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.threads.ThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextClosedEvent;

@Configuration("33E7A5C4-8FAD-4E78-84A4-34451EA32464")
public class TomcatConfig {
  private static final Logger logger = LoggerFactory.getLogger(TomcatConfig.class);

  // This is part of implementing a graceful shutdown
  // per the comments on https://github.com/spring-projects/spring-boot/issues/4657
  // This can be removed when we upgrade to Spring 2.3+ because
  // graceful shutdown has been incorporated into Spring Boot 2.3
  // https://docs.spring.io/spring-boot/docs/2.3.0.BUILD-SNAPSHOT/reference/html/spring-boot-features.html#boot-features-graceful-shutdown
  @Bean("FDBE286E-6EDB-40E9-8E25-D37E0E18D97D")
  public GracefulShutdown getGracefulShutdown() {
    logger.debug("getGracefulShutdown");
    return new GracefulShutdown();
  }

  // This is part of implementing a graceful shutdown
  // per the comments on https://github.com/spring-projects/spring-boot/issues/4657
  // This can be removed when we upgrade to Spring 2.3+ because
  // graceful shutdown has been incorporated into Spring Boot 2.3
  // https://docs.spring.io/spring-boot/docs/2.3.0.BUILD-SNAPSHOT/reference/html/spring-boot-features.html#boot-features-graceful-shutdown
  @Bean("A7347F25-0E03-4771-919F-3565EFADAFA5")
  public WebServerFactoryCustomizer<TomcatServletWebServerFactory> getCustomizer(
      GracefulShutdown gracefulShutdown) {
    logger.debug("getCustomizer");
    return new WebServerFactoryCustomizer<TomcatServletWebServerFactory>() {
      @Override
      public void customize(TomcatServletWebServerFactory factory) {
        logger.debug("customize");
        factory.addConnectorCustomizers(gracefulShutdown);
      }
    };
  }

  // This is part of implementing a graceful shutdown
  // per the comments on https://github.com/spring-projects/spring-boot/issues/4657
  // This can be removed when we upgrade to Spring 2.3+ because
  // graceful shutdown has been incorporated into Spring Boot 2.3
  // https://docs.spring.io/spring-boot/docs/2.3.0.BUILD-SNAPSHOT/reference/html/spring-boot-features.html#boot-features-graceful-shutdown
  public static class GracefulShutdown
      implements TomcatConnectorCustomizer, ApplicationListener<ContextClosedEvent> {
    private static final Logger logger = LoggerFactory.getLogger(GracefulShutdown.class);

    private volatile Connector connector;

    @Override
    public void customize(Connector connector) {
      logger.debug("customize");
      this.connector = connector;
    }

    @Override
    public void onApplicationEvent(ContextClosedEvent event) {
      logger.debug("onApplicationEvent");
      this.connector.pause();
      Executor executor = this.connector.getProtocolHandler().getExecutor();
      if (executor instanceof ThreadPoolExecutor) {
        try {
          ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) executor;
          threadPoolExecutor.shutdown();
          if (!threadPoolExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
            logger.warn(
                "Tomcat thread pool did not shut down gracefully within "
                    + "30 seconds. Proceeding with forceful shutdown");
          }
        } catch (InterruptedException ex) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }
}
