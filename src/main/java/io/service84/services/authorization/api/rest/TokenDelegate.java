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

package io.service84.services.authorization.api.rest;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import io.service84.library.authutils.services.AuthenticationService;
import io.service84.library.authutils.services.BasicAuthenticationXCoder;
import io.service84.library.authutils.services.BasicAuthenticationXCoder.BasicAuthentication;
import io.service84.library.exceptionalresult.models.ExceptionalException;
import io.service84.library.standardservice.services.RequestService;
import io.service84.services.authorization.api.TokenApiDelegate;
import io.service84.services.authorization.api.rest.exceptionalresults.AuthenticationFailedResult;
import io.service84.services.authorization.api.rest.exceptionalresults.ExcessiveDurationRequested;
import io.service84.services.authorization.api.rest.exceptionalresults.InternalServerError;
import io.service84.services.authorization.api.rest.exceptionalresults.UngrantedScope;
import io.service84.services.authorization.dto.ImpersonatedTokenRequestDTO;
import io.service84.services.authorization.dto.PublicKeyListDTO;
import io.service84.services.authorization.dto.TokenDTO;
import io.service84.services.authorization.dto.TokenRequestDTO;
import io.service84.services.authorization.exceptions.AuthenticationFailed;
import io.service84.services.authorization.exceptions.ExceededMaxDurationException;
import io.service84.services.authorization.exceptions.UngrantedScopeException;
import io.service84.services.authorization.persistence.model.PublicKey;
import io.service84.services.authorization.services.KeyService;
import io.service84.services.authorization.services.TokenService;
import io.service84.services.authorization.services.Translator;

@Service("87101422-7DC9-497F-9A6B-6F5C7B885B8D")
public class TokenDelegate implements TokenApiDelegate {
  private static Logger logger = LoggerFactory.getLogger(TokenDelegate.class);

  @Autowired private BasicAuthenticationXCoder basicAuthenticationParser;

  @Autowired private KeyService keyService;
  @Autowired private TokenService tokenService;
  @Autowired private AuthenticationService authenticationService;
  @Autowired private RequestService requestService;
  @Autowired private Translator translator;

  @Override
  public ResponseEntity<TokenDTO> exchangeToken(TokenRequestDTO body, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      String token = tokenService.exchangeToken(body.getDuration(), body.getScopes());
      ResponseEntity<TokenDTO> result = translator.translateToken(token, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (UngrantedScopeException e) {
      logger.info("Ungranted Scope");
      throw new UngrantedScope();
    } catch (ExceededMaxDurationException e) {
      logger.info("Excessive Duration Requested");
      throw new ExcessiveDurationRequested();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<PublicKeyListDTO> getJwks() {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      List<PublicKey> publicKeys = keyService.getRSA512PulicKeys();
      ResponseEntity<PublicKeyListDTO> result =
          translator.translatePublicKeyList(publicKeys, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<TokenDTO> impersonateIdentity(
      ImpersonatedTokenRequestDTO body, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      String token =
          tokenService.impersonateIdentity(
              body.getIdentity(), body.getDuration(), body.getScopes());
      ResponseEntity<TokenDTO> result = translator.translateToken(token, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (UngrantedScopeException e) {
      logger.info("Ungranted Scope");
      throw new UngrantedScope();
    } catch (ExceededMaxDurationException e) {
      logger.info("Excessive Duration Requested");
      throw new ExcessiveDurationRequested();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }

  @Override
  public ResponseEntity<TokenDTO> requestToken(TokenRequestDTO body, String authentication) {
    try {
      logger.info(
          "{} {} {}",
          authenticationService.getSubject(),
          requestService.getMethod(),
          requestService.getURL());
      BasicAuthentication parsedAuthentication = basicAuthenticationParser.decode(authentication);

      if (parsedAuthentication == null) {
        logger.info("Authentication Failed");
        throw new AuthenticationFailedResult();
      }

      String token =
          tokenService.requestToken(
              UUID.fromString(parsedAuthentication.identifier),
              parsedAuthentication.secret,
              body.getDuration(),
              body.getScopes());
      ResponseEntity<TokenDTO> result = translator.translateToken(token, HttpStatus.OK);
      logger.info("OK");
      return result;
    } catch (AuthenticationFailed e) {
      logger.info("Authentication Failed");
      throw new AuthenticationFailedResult();
    } catch (UngrantedScopeException e) {
      logger.info("Ungranted Scope");
      throw new UngrantedScope();
    } catch (ExceededMaxDurationException e) {
      logger.info("Excessive Duration Requested");
      throw new ExcessiveDurationRequested();
    } catch (ExceptionalException e) {
      throw e;
    } catch (Throwable t) {
      logger.error(t.getMessage(), t);
      throw new InternalServerError();
    }
  }
}
