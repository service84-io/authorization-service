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

import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

import io.service84.services.authorization.errors.ServerError;
import io.service84.services.authorization.exceptions.ExceededMaxDurationException;
import io.service84.services.authorization.services.JWTService;

@Service("24F6923C-F5D7-4FFD-8774-109514B505C8")
public class ServiceBootstrapAuthentication {
  private static final Logger logger =
      LoggerFactory.getLogger(ServiceBootstrapAuthentication.class);

  private static String AuthenticateAnyAPIKey = "apikey:authenticate_any_api_key";
  private static String RetrieveAnyAPIKey = "apikey:retrieve_any_api_key";
  private static String GetAnyScope = "permission:get_any_scope";
  private static String GetAnySubjectScopes = "permission:get_any_subject_scopes";

  private static String BEARER_PREFIX = "Bearer ";

  private static UUID BootstrapSubject = UUID.fromString("6A712237-F6A5-4ECF-ABE1-BA83D652D124");
  private static List<String> BootstrapScopes =
      Arrays.asList(AuthenticateAnyAPIKey, RetrieveAnyAPIKey, GetAnyScope, GetAnySubjectScopes);

  @Autowired private JWTService jwtService;

  @Value("${io.service84.services.authorization.jwt_max_duration}")
  private Integer bootstrapDuration;

  @Value("${io.service84.services.authorization.bootstrap_grace_period}")
  private Integer bootstrapGracePeriod;

  private String bootstrapToken = null;
  private String bootstrapBearerToken = null;
  private DecodedJWT bootstrapDecodedJWT = null;

  private void cacheBootstrapDecodedJWT() {
    try {
      bootstrapToken = jwtService.createToken(BootstrapSubject, bootstrapDuration, BootstrapScopes);
      bootstrapBearerToken = BEARER_PREFIX + bootstrapToken;
      bootstrapDecodedJWT = JWT.decode(bootstrapToken);
    } catch (ExceededMaxDurationException e) {
      throw new ServerError();
    }
  }

  private void checkBootstrapDecodedJWT() {
    if ((bootstrapToken == null) || (bootstrapDecodedJWT == null)) {
      cacheBootstrapDecodedJWT();
    } else {
      Date nowish = Date.from(ZonedDateTime.now().plusSeconds(bootstrapGracePeriod).toInstant());

      if (bootstrapDecodedJWT.getExpiresAt().before(nowish)) {
        cacheBootstrapDecodedJWT();
      }
    }
  }

  public String getBootstrapToken() {
    logger.debug("getBootstrapToken");
    checkBootstrapDecodedJWT();
    return bootstrapBearerToken;
  }
}
