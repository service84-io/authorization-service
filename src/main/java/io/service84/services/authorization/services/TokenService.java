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

package io.service84.services.authorization.services;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import io.service84.clients.apikey.dto.APIKeyDTO;
import io.service84.clients.permission.dto.SubjectScopePageDTO;
import io.service84.library.authutils.services.AuthenticationService;
import io.service84.services.authorization.configurations.ServiceBootstrapAuthentication;
import io.service84.services.authorization.exceptions.AuthenticationFailed;
import io.service84.services.authorization.exceptions.ExceededMaxDurationException;
import io.service84.services.authorization.exceptions.UngrantedScopeException;
import io.service84.services.authorization.facades.ApiKeyFacade;
import io.service84.services.authorization.facades.ImpersonationFacade;
import io.service84.services.authorization.facades.SubjectScopeFacade;

@Service("10448BCC-85ED-4676-8831-637FC63E4327")
public class TokenService {
  private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

  private static Integer METADATA = 1;

  private static String IsAuthenticationToken = "IsAuthenticationToken";

  @Autowired private JWTService jwtService;
  @Autowired private AuthenticationService authenticationService;
  @Autowired private ServiceBootstrapAuthentication serviceAuthentication;
  @Autowired private ApiKeyFacade apiKeyFacade;
  @Autowired private ImpersonationFacade impersonationFacade;
  @Autowired private SubjectScopeFacade subjectScopeFacade;

  public String exchangeToken(Integer duration, List<String> scopes)
      throws UngrantedScopeException, ExceededMaxDurationException {
    logger.debug("exchangeToken");
    List<String> subjectScopes = authenticationService.getScopes();

    if (subjectScopes.contains(IsAuthenticationToken)) {
      UUID subject = UUID.fromString(authenticationService.getSubject());
      String bootstrapToken = serviceAuthentication.getBootstrapToken();

      SubjectScopePageDTO subjectScopePage =
          subjectScopeFacade.getSubjectScopes(
              bootstrapToken, Collections.singletonList(subject), scopes, null, METADATA);

      if (subjectScopePage.getMetadata().getTotal() == scopes.size()) {
        return jwtService.createToken(subject, duration, scopes);
      }
    }

    throw new UngrantedScopeException();
  }

  public String impersonateIdentity(@Valid UUID identity, Integer duration, List<String> scopes)
      throws UngrantedScopeException, ExceededMaxDurationException {
    logger.debug("impersonateIdentity");
    String authentication = authenticationService.getAuthenticationToken();

    /*AssumableIdentityDTO*/ Object assumedIdentity =
        impersonationFacade.assumeIdentity(authentication, identity);
    String bootstrapToken = serviceAuthentication.getBootstrapToken();
    /*SubjectScopePageDTO subjectScopePage =
        subjectScopeFacade.getSubjectScopes(
            bootstrapToken,
            Collections.singletonList(assumedIdentity.getIdentity()),
            scopes,
            null,
            METADATA);

    if (subjectScopePage.getMetadata().getTotal() == scopes.size()) {
      return jwtService.createToken(assumedIdentity.getIdentity(), duration, scopes);
    }*/

    throw new UngrantedScopeException();
  }

  public String requestToken(
      @Valid UUID apiKeyId, String apiKeySecret, Integer duration, List<String> scopes)
      throws UngrantedScopeException, ExceededMaxDurationException, AuthenticationFailed {
    logger.debug("requestToken");
    String bootstrapToken = serviceAuthentication.getBootstrapToken();
    APIKeyDTO apiKey = apiKeyFacade.authenticateApiKey(bootstrapToken, apiKeyId, apiKeySecret);
    UUID apiKeyIdentidier = apiKey.getId();
    UUID subject = apiKey.getSubject();

    SubjectScopePageDTO apiKeyScopePage =
        subjectScopeFacade.getSubjectScopes(
            bootstrapToken, Collections.singletonList(apiKeyIdentidier), scopes, null, METADATA);

    SubjectScopePageDTO subjectScopePage =
        subjectScopeFacade.getSubjectScopes(
            bootstrapToken, Collections.singletonList(subject), scopes, null, METADATA);

    if ((apiKeyScopePage.getMetadata().getTotal() == scopes.size())
        && (subjectScopePage.getMetadata().getTotal() == scopes.size())) {
      return jwtService.createToken(subject, duration, scopes);
    }

    throw new UngrantedScopeException();
  }
}
