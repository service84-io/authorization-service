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

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;

import io.service84.library.authutils.services.AuthenticationService;

@Configuration("4F41B33E-CD60-424B-81B4-6C4CF5A6D187")
public class AuditorAwareConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(AuditorAwareConfiguration.class);

  private static class AuditorAwareImpl implements AuditorAware<String> {
    private static final Logger logger = LoggerFactory.getLogger(AuditorAwareImpl.class);

    @Autowired private AuthenticationService authenticationService;

    @Override
    public Optional<String> getCurrentAuditor() {
      logger.debug("getCurrentAuditor");
      return Optional.ofNullable(authenticationService.getSubject());
    }
  }

  @Bean("5611BDAC-526E-4446-83FA-14F38A0D1525")
  public AuditorAware<String> getAuditorAware() {
    logger.debug("getAuditorAware");
    return new AuditorAwareImpl();
  }
}
