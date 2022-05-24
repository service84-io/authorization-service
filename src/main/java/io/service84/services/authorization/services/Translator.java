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

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import io.service84.library.standardpersistence.services.PaginationTranslator;
import io.service84.services.authorization.dto.PublicKeyDTO;
import io.service84.services.authorization.dto.PublicKeyListDTO;
import io.service84.services.authorization.dto.TokenDTO;
import io.service84.services.authorization.persistence.model.PublicKey;

@Service("56C75DCA-FC81-40CC-992F-F8125863F8D2")
public class Translator extends PaginationTranslator {
  private static final Logger logger = LoggerFactory.getLogger(Translator.class);

  public PublicKeyDTO translate(PublicKey entity) {
    logger.debug("translate");
    if (entity == null) {
      return null;
    }

    RSAPublicKey rsaPublicKey = entity.getKey();
    PublicKeyDTO dto = new PublicKeyDTO();
    dto.setAlg(entity.getAlgorithm());
    dto.setE(Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray()));
    dto.setKid(entity.getId().toString());
    dto.setKty(rsaPublicKey.getAlgorithm());
    dto.setN(Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray()));
    dto.setUse("sig");
    return dto;
  }

  public ResponseEntity<PublicKeyDTO> translate(PublicKey entity, HttpStatus status) {
    logger.debug("translate");
    return new ResponseEntity<>(translate(entity), status);
  }

  public PublicKeyListDTO translatePublicKeyList(List<PublicKey> list) {
    logger.debug("translatePublicKeyList");
    if (list == null) {
      return null;
    }

    List<PublicKeyDTO> keys = list.stream().map(e -> translate(e)).collect(Collectors.toList());
    return new PublicKeyListDTO().keys(keys);
  }

  public ResponseEntity<PublicKeyListDTO> translatePublicKeyList(
      List<PublicKey> list, HttpStatus status) {
    logger.debug("translatePublicKeyList");
    return new ResponseEntity<>(translatePublicKeyList(list), status);
  }

  public TokenDTO translateToken(String token) {
    logger.debug("translateToken");
    if (token == null) {
      return null;
    }

    TokenDTO dto = new TokenDTO();
    dto.setToken(token);
    return dto;
  }

  public ResponseEntity<TokenDTO> translateToken(String token, HttpStatus status) {
    logger.debug("translateToken");
    return new ResponseEntity<>(translateToken(token), status);
  }
}
