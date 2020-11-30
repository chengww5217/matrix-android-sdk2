/*
 * Copyright 2020 The Matrix.org Foundation C.I.C.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.matrix.android.sdk.api.auth.login

import org.matrix.android.sdk.api.MatrixCallback
import org.matrix.android.sdk.api.session.Session
import org.matrix.android.sdk.api.util.Cancelable

interface LoginWizard {

    /**
     * @param login the login field
     * @param password the password field
     * @param deviceName the initial device name
     * @param callback  the matrix callback on which you'll receive the result of authentication.
     * @return return a [Cancelable]
     */
    fun login(login: String,
              password: String,
              deviceName: String,
              callback: MatrixCallback<Session>): Cancelable

    /**
     * Exchange a login token to an access token
     */
    fun loginWithToken(loginToken: String,
                       callback: MatrixCallback<Session>): Cancelable

    /**
     * Reset user password
     */
    fun resetPassword(email: String,
                      newPassword: String,
                      callback: MatrixCallback<Unit>): Cancelable

    /**
     * Confirm the new password, once the user has checked his email
     */
    fun resetPasswordMailConfirmed(callback: MatrixCallback<Unit>): Cancelable

    /**
     * To support verification code login of each chat
     *
     * @see [org.matrix.android.sdk.internal.auth.login.VerCodeLoginParams]
     * @param type one of the
     * [org.matrix.android.sdk.internal.auth.login.EACHCHAT_MSISDN_CODE] or
     * [org.matrix.android.sdk.internal.auth.login.EACHCHAT_EMAIL_CODE]
     *
     * @param address email or phone number
     * @param verCode the verification code
     * @param deviceName device name of the [Session]
     * @param callback call after the request called
     * @return a cancelable task. Call Cancelable.cancel() when your screen is onDestroy
     */
    fun verCodeLogin(
            type: String,
            address: String,
            verCode: String,
            deviceName: String?,
            callback: MatrixCallback<Session>
    ): Cancelable

    fun oauthLogin(type: String,
                   code: String,
                   deviceName: String?,
                   callback: MatrixCallback<Session>
    ): Cancelable

    fun ldapLogin(user: String,
                  password: String,
                  deviceName: String?,
                  callback: MatrixCallback<Session>
    ): Cancelable
}
