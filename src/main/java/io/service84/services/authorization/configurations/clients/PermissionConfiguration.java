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

import io.service84.clients.permission.ApiClient;

@Configuration("FAA7C70A-1004-43B3-A219-3A586E93920E")
public class PermissionConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(PermissionConfiguration.class);

  @Autowired
  public PermissionConfiguration(
      ApiClient apiClient, @Value("${io.service84.clients.permission.url}") String permissionURL) {
    logger.debug("PermissionConfiguration");
    apiClient.setBasePath(permissionURL);
  }
}
