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

import io.service84.clients.impersonation.ApiClient;

@Configuration("46DBA317-F86D-4793-8122-43126F50B3CE")
public class ImpersonationConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(ImpersonationConfiguration.class);

  @Autowired
  public ImpersonationConfiguration(
      ApiClient apiClient,
      @Value("${io.service84.clients.impersonation.url}") String impersonationURL) {
    logger.debug("ImpersonationConfiguration");
    apiClient.setBasePath(impersonationURL);
  }
}
