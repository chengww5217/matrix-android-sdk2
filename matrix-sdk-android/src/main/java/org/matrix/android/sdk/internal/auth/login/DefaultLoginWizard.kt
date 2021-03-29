/*
 * Copyright 2020 The Matrix.org Foundation C.I.C.
 *
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

package org.matrix.android.sdk.internal.auth.login

import android.util.Patterns
import org.matrix.android.sdk.api.MatrixCallback
import org.matrix.android.sdk.api.auth.data.Credentials
import org.matrix.android.sdk.api.auth.login.LoginWizard
import org.matrix.android.sdk.api.auth.registration.RegisterThreePid
import org.matrix.android.sdk.api.session.Session
import org.matrix.android.sdk.api.util.Cancelable
import org.matrix.android.sdk.internal.auth.AuthAPI
import org.matrix.android.sdk.internal.auth.PendingSessionStore
import org.matrix.android.sdk.internal.auth.SessionCreator
import org.matrix.android.sdk.internal.auth.data.PasswordLoginParams
import org.matrix.android.sdk.internal.auth.data.ThreePidMedium
import org.matrix.android.sdk.internal.auth.data.TokenLoginParams
import org.matrix.android.sdk.internal.auth.db.PendingSessionData
import org.matrix.android.sdk.internal.auth.registration.AddThreePidRegistrationParams
import org.matrix.android.sdk.internal.auth.registration.AddThreePidRegistrationResponse
import org.matrix.android.sdk.internal.auth.registration.RegisterAddThreePidTask
import org.matrix.android.sdk.internal.network.executeRequest

internal class DefaultLoginWizard(
        private val authAPI: AuthAPI,
        private val sessionCreator: SessionCreator,
        private val pendingSessionStore: PendingSessionStore
) : LoginWizard {

    private var pendingSessionData: PendingSessionData = pendingSessionStore.getPendingSessionData() ?: error("Pending session data should exist here")

    override suspend fun login(login: String,
                               password: String,
                               deviceName: String): Session {
        val loginParams = if (Patterns.EMAIL_ADDRESS.matcher(login).matches()) {
            PasswordLoginParams.thirdPartyIdentifier(ThreePidMedium.EMAIL, login, password, deviceName)
        } else {
            PasswordLoginParams.userIdentifier(login, password, deviceName)
        }
        val credentials = executeRequest<Credentials>(null) {
            apiCall = authAPI.login(loginParams)
        }

        return sessionCreator.createSession(credentials, pendingSessionData.homeServerConnectionConfig)
    }

    /**
     * Ref: https://matrix.org/docs/spec/client_server/latest#handling-the-authentication-endpoint
     */
    override suspend fun loginWithToken(loginToken: String): Session {
        val loginParams = TokenLoginParams(
                token = loginToken
        )
        val credentials = executeRequest<Credentials>(null) {
            apiCall = authAPI.login(loginParams)
        }

        return sessionCreator.createSession(credentials, pendingSessionData.homeServerConnectionConfig)
    }

    override suspend fun resetPassword(email: String, newPassword: String) {
        val param = RegisterAddThreePidTask.Params(
                RegisterThreePid.Email(email),
                pendingSessionData.clientSecret,
                pendingSessionData.sendAttempt
        )

        pendingSessionData = pendingSessionData.copy(sendAttempt = pendingSessionData.sendAttempt + 1)
                .also { pendingSessionStore.savePendingSessionData(it) }

        val result = executeRequest<AddThreePidRegistrationResponse>(null) {
            apiCall = authAPI.resetPassword(AddThreePidRegistrationParams.from(param))
        }

        pendingSessionData = pendingSessionData.copy(resetPasswordData = ResetPasswordData(newPassword, result))
                .also { pendingSessionStore.savePendingSessionData(it) }
    }

    override suspend fun resetPasswordMailConfirmed() {
        val safeResetPasswordData = pendingSessionData.resetPasswordData
                ?: throw IllegalStateException("developer error, no reset password in progress")
        val param = ResetPasswordMailConfirmed.create(
                pendingSessionData.clientSecret,
                safeResetPasswordData.addThreePidRegistrationResponse.sid,
                safeResetPasswordData.newPassword
        )

        executeRequest<Unit>(null) {
            apiCall = authAPI.resetPasswordMailConfirmed(param)
        }

        // Set to null?
        // resetPasswordData = null
    }

    override suspend fun verCodeLogin(type: String, address: String, verCode: String, deviceName: String?): Session {
        val input = when (type) {
            EACHCHAT_MSISDN_CODE -> VerCodeLoginParams(EACHCHAT_MSISDN_CODE, null, address, verCode, deviceName)
            EACHCHAT_EMAIL_CODE -> VerCodeLoginParams(EACHCHAT_EMAIL_CODE, address, null, verCode, deviceName)
            else -> null
        } ?: throw RuntimeException("Developer error, type must be one of the m.login.verCode.msisdn and m.login.verCode.email")

        val credentials = executeRequest<Credentials>(null) {
            apiCall = authAPI.verCodeLogin(input)
        }

        return sessionCreator.createSession(credentials, pendingSessionData.homeServerConnectionConfig)
    }

    override suspend fun oauthLogin(type: String, code: String, deviceName: String?): Session {
        val input = OAuthLoginParams(type, code, deviceName)

        val credentials = executeRequest<Credentials>(null) {
            apiCall = authAPI.oauthLogin(input)
        }

        return sessionCreator.createSession(credentials, pendingSessionData.homeServerConnectionConfig)
    }

    override suspend fun ldapLogin(user: String, password: String, deviceName: String?): Session {
        val input = LdapLoginParams(user, password, deviceName)

        val credentials = executeRequest<Credentials>(null) {
            apiCall = authAPI.ldapLogin(input)
        }

        return sessionCreator.createSession(credentials, pendingSessionData.homeServerConnectionConfig)
    }

}
