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

package io.service84.services.authorization.facades;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import io.service84.services.authorization.errors.ServerError;

@Service("ECF625D9-420F-42F5-A7CA-F5A79FBDB2BD")
public class ImpersonationFacade {
  private static final Logger logger = LoggerFactory.getLogger(ImpersonationFacade.class);

  // @Autowired private ImpersonationApi impersonationApi;

  public /*AssumableIdentityDTO*/ Object assumeIdentity(String authentication, UUID identity) {
    logger.debug("assumeIdentity");
    /*
    try {
      IdentityRequestDTO assumeIdentityRequest = new IdentityRequestDTO();
      assumeIdentityRequest.setIdentity(identity);
      return impersonationApi.assumeIdentity(assumeIdentityRequest, authentication);
    } catch (HttpStatusCodeException e) {
      if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)) {
        throw new ServerError(e);
      }*/

    throw new ServerError(/*e*/ );
    // }
  }
}
