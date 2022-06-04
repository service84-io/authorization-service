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

package io.service84.services.authorization.configurations.clients;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import io.service84.clients.apikey.ApiClient;

@Configuration("645292C7-7310-492C-B709-37746DB078C8")
public class APIKeyConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(APIKeyConfiguration.class);

  @Autowired
  public APIKeyConfiguration(
      ApiClient apiClient, @Value("${io.service84.clients.apikey.url}") String apikeyURL) {
    logger.debug("APIKeyConfiguration");
    apiClient.setBasePath(apikeyURL);
  }
}
