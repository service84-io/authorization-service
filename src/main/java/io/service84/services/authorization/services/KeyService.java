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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.interfaces.RSAKeyProvider;

import io.service84.library.keyvaluepersistence.exceptions.KeyNotFound;
import io.service84.library.keyvaluepersistence.services.KeyValueService;
import io.service84.services.authorization.errors.ServerError;
import io.service84.services.authorization.persistence.model.PublicKey;
import io.service84.services.authorization.persistence.repository.PublicKeyRepository;

@Service("D524F7E3-7F86-472F-9ACE-CD9F085FCAE7")
public class KeyService {
  private static final Logger logger = LoggerFactory.getLogger(KeyService.class);

  public static class S84KeyPair {
    public String privateKey;
    public UUID publicKeyId;
  }

  private static String CurrentS84KeyPair = "CurrentS84KeyPair";
  private static String NextS84KeyPair = "NextS84KeyPair";
  private static String NextS84KeyPairGeneratedAt = "NextS84KeyPairGeneratedAt";

  @Autowired private KeyValueService kvService;
  @Autowired private PublicKeyRepository publicKeyRepository;

  private KeyFactory rsaKeyFactory;

  private UUID rsaKeyId;
  private RSAPrivateKey rsaPrivateKey;

  @Value("${io.service84.services.authorization.seconds_to_cache}")
  private Integer secondsToCache;

  public KeyService() {
    try {
      rsaKeyFactory = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      throw new ServerError();
    }
  }

  private void activateAndReplaceNextS84KeyPair() {
    activateNextS84KeyPair();
    generateNextS84KeyPair();
  }

  private void activateNextS84KeyPair() {
    try {
      S84KeyPair nextKeyPair = kvService.getValue(NextS84KeyPair, S84KeyPair.class);
      LocalDateTime nextKeyPairGeneratedAt =
          kvService.getValue(NextS84KeyPairGeneratedAt, LocalDateTime.class);

      if ((nextKeyPair != null) && (nextKeyPairGeneratedAt != null)) {
        UUID nextPublicKeyId = nextKeyPair.publicKeyId;
        List<PublicKey> recentlyObsoletedPublicKeys =
            publicKeyRepository.findByLastUsedAfter(LocalDateTime.now()).stream()
                .filter(pk -> pk.getId() != nextPublicKeyId)
                .collect(Collectors.toList());

        for (PublicKey publicKey : recentlyObsoletedPublicKeys) {
          publicKey.setLastUsed(LocalDateTime.now());
        }

        kvService.setValue(CurrentS84KeyPair, nextKeyPair);
        publicKeyRepository.saveAll(recentlyObsoletedPublicKeys);
      }
    } catch (KeyNotFound e) {
      // Its not a big deal if we don't find a key to activate.
    } finally {
      kvService.setValue(NextS84KeyPair, null);
      kvService.setValue(NextS84KeyPairGeneratedAt, null);
    }
  }

  private void asyncActivateAndReplaceNextS84KeyPair() {
    new Thread(() -> activateAndReplaceNextS84KeyPair()).start();
  }

  private void asyncGenerateNextS84KeyPair() {
    new Thread(() -> generateNextS84KeyPair()).start();
  }

  private void fetchRSAKey() {
    try {
      S84KeyPair keyPair = kvService.getValue(CurrentS84KeyPair, S84KeyPair.class);
      if (!keyPair.publicKeyId.equals(rsaKeyId)) {
        PKCS8EncodedKeySpec privateKeySpec =
            new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyPair.privateKey));
        rsaPrivateKey = (RSAPrivateKey) rsaKeyFactory.generatePrivate(privateKeySpec);
        rsaKeyId = keyPair.publicKeyId;
      }
    } catch (KeyNotFound e) {
      generateNextS84KeyPair();
      activateNextS84KeyPair();
      generateNextS84KeyPair();
      fetchRSAKey();
    } catch (InvalidKeySpecException e) {
      throw new ServerError();
    }
  }

  private void generateNextS84KeyPair() {
    try {
      KeyPairGenerator keyGen;
      keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(4096);
      KeyPair keyPair = keyGen.genKeyPair();
      RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
      RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
      PublicKey publicKey = new PublicKey(rsaPublicKey, "RS512");
      publicKey = publicKeyRepository.save(publicKey);
      S84KeyPair s84KeyPair = new S84KeyPair();
      s84KeyPair.privateKey =
          Base64.getEncoder()
              .encodeToString(
                  rsaKeyFactory.getKeySpec(rsaPrivateKey, PKCS8EncodedKeySpec.class).getEncoded());
      s84KeyPair.publicKeyId = publicKey.getId();
      kvService.setValue(NextS84KeyPair, s84KeyPair);
      kvService.setValue(NextS84KeyPairGeneratedAt, LocalDateTime.now());
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new ServerError();
    }
  }

  public Integer getPublicKeyCacheSeconds() {
    logger.debug("getPublicKeyCacheSeconds");
    return secondsToCache;
  }

  public RSAKeyProvider getRSA512KeyProvider() {
    logger.debug("getRSA512KeyProvider");
    try {
      fetchRSAKey();

      LocalDateTime nextKeyPairGeneratedAt =
          kvService.getValue(NextS84KeyPairGeneratedAt, LocalDateTime.class);

      if (nextKeyPairGeneratedAt == null) {
        asyncGenerateNextS84KeyPair();
      } else if (nextKeyPairGeneratedAt.isBefore(
          LocalDateTime.now().minusSeconds(secondsToCache))) {
        asyncActivateAndReplaceNextS84KeyPair();
      }

      List<PublicKey> publicKeys = getRSA512PulicKeys();

      return new RSAKeyProvider() {
        @Override
        public RSAPrivateKey getPrivateKey() {
          return rsaPrivateKey;
        }

        @Override
        public String getPrivateKeyId() {
          return rsaKeyId.toString();
        }

        @Override
        public RSAPublicKey getPublicKeyById(String keyId) {
          UUID keyUUID = UUID.fromString(keyId);
          return publicKeys.stream()
              .filter(pk -> pk.getId().equals(keyUUID))
              .map(pk -> pk.getKey())
              .findAny()
              .orElse(null);
        }
      };
    } catch (KeyNotFound e) {
      generateNextS84KeyPair();
      activateNextS84KeyPair();
      generateNextS84KeyPair();
      return getRSA512KeyProvider();
    }
  }

  public List<PublicKey> getRSA512PulicKeys() {
    logger.debug("getRSA512PulicKeys");
    fetchRSAKey();
    return publicKeyRepository.findByLastUsedAfter(
        LocalDateTime.now().minusSeconds(secondsToCache));
  }
}
