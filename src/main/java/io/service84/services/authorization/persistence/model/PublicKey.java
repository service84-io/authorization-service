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

package io.service84.services.authorization.persistence.model;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import org.hibernate.annotations.GenericGenerator;
import org.hibernate.envers.Audited;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import io.service84.services.authorization.errors.ServerError;

@Entity
@Audited
@EntityListeners(AuditingEntityListener.class)
public class PublicKey {
  public static LocalDateTime MaxLastUsed = LocalDateTime.of(3000, 1, 1, 0, 0);

  @Id
  @GeneratedValue(generator = "UUID")
  @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
  private UUID id;

  @CreatedDate private LocalDateTime createdDate;
  @CreatedBy private String createdBy;
  @LastModifiedDate private LocalDateTime modifiedDate;
  @LastModifiedBy private String modifiedBy;

  @Column(nullable = false, columnDefinition = "VARCHAR(65535)")
  private String key;

  @Column(nullable = false)
  private String algorithm;

  @Column(nullable = false)
  private LocalDateTime lastUsed;

  protected PublicKey() {}

  public PublicKey(RSAPublicKey key, String algorithm) {
    this.key = Base64.getEncoder().encodeToString(key.getEncoded());
    this.algorithm = algorithm;
    this.lastUsed = MaxLastUsed;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public UUID getId() {
    return id;
  }

  public RSAPublicKey getKey() {
    try {
      X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new ServerError();
    }
  }

  public void setLastUsed(LocalDateTime lastUsed) {
    this.lastUsed = lastUsed;
  }
}
