import unittest
from unittest.mock import Mock, patch

from services.register import openai_register


class ExistingAccountAuthenticationTests(unittest.TestCase):
    def _registrar(self) -> openai_register.PlatformRegistrar:
        registrar = openai_register.PlatformRegistrar.__new__(openai_register.PlatformRegistrar)
        registrar._platform_authorize = Mock()
        registrar._send_login_otp = Mock()
        return registrar

    def test_existing_login_exchanges_platform_oauth_tokens_after_password_login(self) -> None:
        registrar = self._registrar()
        registrar._password_verify = Mock(return_value=("https://auth.openai.com/continue/password", ""))
        registrar._login_and_exchange_tokens = Mock(
            return_value={
                "access_token": "platform-access",
                "refresh_token": "platform-refresh",
                "id_token": "platform-id",
            }
        )

        result = registrar.authenticate_existing(
            "user@example.com",
            {"address": "user@example.com"},
            "password-1",
            7,
        )

        registrar._platform_authorize.assert_called_once_with("user@example.com", 7, screen_hint="login")
        registrar._password_verify.assert_called_once_with("password-1", 7)
        registrar._send_login_otp.assert_not_called()
        registrar._login_and_exchange_tokens.assert_called_once_with(
            "user@example.com",
            "password-1",
            {"address": "user@example.com"},
            "https://auth.openai.com/continue/password",
            7,
        )
        self.assertEqual(result["access_token"], "platform-access")
        self.assertEqual(result["refresh_token"], "platform-refresh")
        self.assertEqual(result["id_token"], "platform-id")

    def test_existing_login_uses_otp_continue_url_for_platform_oauth_exchange(self) -> None:
        registrar = self._registrar()
        registrar._password_verify = Mock(return_value=("https://auth.openai.com/continue/password", "email_otp_verification"))
        registrar._validate_login_otp = Mock(return_value=("https://auth.openai.com/continue/otp", "done"))
        registrar._login_and_exchange_tokens = Mock(
            return_value={
                "access_token": "otp-platform-access",
                "refresh_token": "otp-platform-refresh",
                "id_token": "otp-platform-id",
            }
        )

        with patch.object(openai_register, "wait_for_code", return_value="123456") as wait_for_code:
            result = registrar.authenticate_existing(
                "user@example.com",
                {"address": "user@example.com"},
                "password-1",
                8,
            )

        wait_for_code.assert_called_once_with({"address": "user@example.com"})
        registrar._send_login_otp.assert_not_called()
        registrar._validate_login_otp.assert_called_once_with("123456", 8)
        registrar._login_and_exchange_tokens.assert_called_once_with(
            "user@example.com",
            "password-1",
            {"address": "user@example.com"},
            "https://auth.openai.com/continue/otp",
            8,
        )
        self.assertEqual(result["access_token"], "otp-platform-access")
        self.assertEqual(result["refresh_token"], "otp-platform-refresh")
        self.assertEqual(result["id_token"], "otp-platform-id")

    def test_existing_login_reauthorizes_after_about_you_continue_url(self) -> None:
        registrar = self._registrar()
        registrar._platform_authorize = Mock(
            side_effect=[
                "https://auth.openai.com/about-you",
                "https://platform.openai.com/auth/callback?code=oauth-code",
            ]
        )
        registrar._password_verify = Mock(return_value=("https://auth.openai.com/continue/password", "email_otp_verification"))
        registrar._validate_login_otp = Mock(return_value=("https://auth.openai.com/about-you", "about_you"))
        registrar._create_account = Mock()
        registrar._login_and_exchange_tokens = Mock(
            return_value={
                "access_token": "reauth-platform-access",
                "refresh_token": "reauth-platform-refresh",
                "id_token": "reauth-platform-id",
            }
        )

        with patch.object(openai_register, "wait_for_code", return_value="939548"):
            result = registrar.authenticate_existing(
                "user@example.com",
                {"address": "user@example.com"},
                "password-1",
                9,
            )

        self.assertEqual(registrar._platform_authorize.call_count, 2)
        registrar._platform_authorize.assert_any_call("user@example.com", 9, screen_hint="login")
        registrar._create_account.assert_not_called()
        registrar._login_and_exchange_tokens.assert_called_once_with(
            "user@example.com",
            "password-1",
            {"address": "user@example.com"},
            "https://platform.openai.com/auth/callback?code=oauth-code",
            9,
        )
        self.assertEqual(result["access_token"], "reauth-platform-access")
        self.assertEqual(result["refresh_token"], "reauth-platform-refresh")
        self.assertEqual(result["id_token"], "reauth-platform-id")


if __name__ == "__main__":
    unittest.main()
