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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;

import io.service84.clients.apikey.api.ApiKeyApi;
import io.service84.clients.apikey.dto.APIKeyAuthenticationDTO;
import io.service84.clients.apikey.dto.APIKeyDTO;
import io.service84.clients.apikey.dto.APIKeyDetailsDTO;
import io.service84.clients.apikey.dto.APIKeyPageDTO;
import io.service84.clients.apikey.dto.APIKeyRequestDTO;
import io.service84.services.authorization.errors.ServerError;
import io.service84.services.authorization.exceptions.AuthenticationFailed;
import io.service84.services.authorization.exceptions.EntityNotFound;

@Service("30200799-8E5E-44A4-80C8-9E1A82567984")
public class ApiKeyFacade {
  private static final Logger logger = LoggerFactory.getLogger(ApiKeyFacade.class);

  @Autowired private ApiKeyApi apiKeyApi;

  public APIKeyDTO authenticateApiKey(String authentication, UUID id, String secret)
      throws AuthenticationFailed {
    logger.debug("authenticateApiKey");
    try {
      APIKeyAuthenticationDTO authenticationRequest = new APIKeyAuthenticationDTO();
      authenticationRequest.setId(id);
      authenticationRequest.setSecret(secret);
      return apiKeyApi.authenticateApiKey(authenticationRequest, authentication);
    } catch (HttpStatusCodeException e) {
      if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.UNAUTHORIZED)) {
        throw new AuthenticationFailed(e);
      }

      if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)) {
        throw new ServerError(e);
      }

      throw new ServerError(e);
    }
  }

  public APIKeyDetailsDTO requestApiKey(String authentication, String name) {
    logger.debug("requestApiKey");
    try {
      APIKeyRequestDTO apiKeyRequest = new APIKeyRequestDTO();
      apiKeyRequest.setName(name);
      return apiKeyApi.requestApiKey(apiKeyRequest, authentication);
    } catch (HttpStatusCodeException e) {
      if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)) {
        throw new ServerError(e);
      }

      throw new ServerError(e);
    }
  }

  public APIKeyDTO retrieveApiKey(String authentication, UUID id) throws EntityNotFound {
    logger.debug("retrieveApiKey");
    try {
      return apiKeyApi.retrieveApiKey(id, authentication);
    } catch (HttpStatusCodeException e) {
      if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
        throw new EntityNotFound(e);
      }

      if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)) {
        throw new ServerError(e);
      }

      throw new ServerError(e);
    }
  }

  public APIKeyPageDTO retrieveApiKeys(String authentication, String pageIndex, Integer pageSize) {
    logger.debug("retrieveApiKeys");
    try {
      return apiKeyApi.retrieveApiKeys(authentication, pageIndex, pageSize);
    } catch (HttpStatusCodeException e) {
      if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)) {
        throw new ServerError(e);
      }

      throw new ServerError(e);
    }
  }

  public void revokeApiKey(String authentication, UUID id) throws EntityNotFound {
    logger.debug("revokeApiKey");
    try {
      apiKeyApi.revokeApiKey(id, authentication);
    } catch (HttpStatusCodeException e) {
      if (e.getStatusCode().equals(HttpStatus.BAD_REQUEST)) {
        throw new ServerError(e);
      }

      if (e.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
        throw new EntityNotFound(e);
      }

      if (e.getStatusCode().equals(HttpStatus.INTERNAL_SERVER_ERROR)) {
        throw new ServerError(e);
      }

      throw new ServerError(e);
    }
  }
}
