package org.matrix.android.sdk.internal.auth.login

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import org.matrix.android.sdk.internal.auth.data.LoginParams

/**
 * Created by chengww on 11/28/20
 *
 * Data class for ldap login input.
 * @author chengww
 */
@JsonClass(generateAdapter = true)
data class LdapLoginParams(
        @Json(name = "user") val user: String,
        @Json(name = "password") val password: String,
        @Json(name = "initial_device_display_name") val deviceDisplayName: String?,
        @Json(name = "type") override val type: String = "m.login.sso.ldap"
) : LoginParams