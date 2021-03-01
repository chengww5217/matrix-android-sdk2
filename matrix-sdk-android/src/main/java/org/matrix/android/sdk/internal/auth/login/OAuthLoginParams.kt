package org.matrix.android.sdk.internal.auth.login

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import org.matrix.android.sdk.internal.auth.data.LoginParams

/**
 * Created by chengww on 11/25/20
 *
 * Data class for oauth login(Alipay/WeChat) input.
 * @param type must be one of the
 * [EACHCHAT_LOGIN_ALIPAY] and
 * [EACHCHAT_LOGIN_WECHAT]
 *
 * @author chengww
 */
@JsonClass(generateAdapter = true)
data class OAuthLoginParams(
        @Json(name = "type") override val type: String,
        @Json(name = "auth_code") val code: String,
        @Json(name = "initial_device_display_name") val deviceDisplayName: String?
) : LoginParams

const val EACHCHAT_LOGIN_ALIPAY = "m.login.OAuth2.alipay"
const val EACHCHAT_LOGIN_WECHAT = "m.login.OAuth2.weixin"