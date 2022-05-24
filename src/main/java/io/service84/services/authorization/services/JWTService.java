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

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import io.service84.services.authorization.exceptions.ExceededMaxDurationException;

@Service("F7E28142-9FB6-4677-9014-9BE76962B4FD")
public class JWTService {
  private static final Logger logger = LoggerFactory.getLogger(JWTService.class);

  @Autowired private KeyService keyService;

  @Value("${io.service84.services.authorization.jwt_max_duration}")
  private Integer maxDuration;

  @Value("${io.service84.services.authorization.issuer}")
  private String issuer;

  public String createToken(UUID subject, Integer duration, List<String> scopes)
      throws ExceededMaxDurationException {
    logger.debug("createToken");
    if (duration > maxDuration) {
      throw new ExceededMaxDurationException();
    }

    Date expiration = Date.from(ZonedDateTime.now().plusSeconds(duration).toInstant());
    RSAKeyProvider keyProvider = keyService.getRSA512KeyProvider();
    Algorithm algorithm = Algorithm.RSA512(keyProvider);
    return JWT.create()
        .withIssuer(issuer)
        .withExpiresAt(expiration)
        .withSubject(subject.toString())
        .withClaim("scope", String.join(" ", scopes))
        .sign(algorithm);
  }
}
