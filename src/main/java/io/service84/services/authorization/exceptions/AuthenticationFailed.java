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

package io.service84.services.authorization.exceptions;

import java.util.function.Supplier;

public class AuthenticationFailed extends Exception {
  private static final long serialVersionUID = 1L;

  public static Supplier<AuthenticationFailed> supplier2() {
    return new Supplier<>() {
      @Override
      public AuthenticationFailed get() {
        return new AuthenticationFailed();
      }
    };
  }

  public AuthenticationFailed() {}

  public AuthenticationFailed(String message) {
    super(message);
  }

  public AuthenticationFailed(String message, Throwable cause) {
    super(message, cause);
  }

  public AuthenticationFailed(Throwable cause) {
    super(cause);
  }
}
