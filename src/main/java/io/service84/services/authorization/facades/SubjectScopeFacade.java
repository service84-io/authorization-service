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

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;

import io.service84.clients.permission.api.SubjectScopeApi;
import io.service84.clients.permission.dto.SubjectScopeDTO;
import io.service84.clients.permission.dto.SubjectScopeDataDTO;
import io.service84.clients.permission.dto.SubjectScopePageDTO;
import io.service84.services.authorization.errors.ServerError;

@Service("BE69D533-0D7D-434F-88B5-893247A79960")
public class SubjectScopeFacade {
  private static final Logger logger = LoggerFactory.getLogger(SubjectScopeFacade.class);

  @Autowired private SubjectScopeApi subjectScopeApi;

  public SubjectScopePageDTO getSubjectScopes(
      String authentication,
      List<UUID> subjects,
      List<String> scopes,
      String pageIndex,
      Integer pageSize) {
    logger.debug("getSubjectScopes");
    try {
      return subjectScopeApi.getSubjectScopes(
          authentication, subjects, scopes, pageIndex, pageSize);
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

  public SubjectScopeDTO grantSubjectScope(String authentication, UUID subject, UUID scopeId) {
    logger.debug("grantSubjectScope");
    try {
      SubjectScopeDataDTO grantRequest = new SubjectScopeDataDTO();
      grantRequest.setSubject(subject);
      grantRequest.setScopeId(scopeId);
      return subjectScopeApi.grantSubjectScope(grantRequest, authentication);
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

  public void revokeSubjectScope(String authentication, UUID subject, UUID scopeId) {
    logger.debug("revokeSubjectScope");
    try {
      SubjectScopeDataDTO revokeRequest = new SubjectScopeDataDTO();
      revokeRequest.setSubject(subject);
      revokeRequest.setScopeId(scopeId);
      subjectScopeApi.revokeSubjectScope(revokeRequest, authentication);
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
}
