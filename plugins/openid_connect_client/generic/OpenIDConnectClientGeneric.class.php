<?php

/**
 * @file
 * Generic OpenID Connect client.
 *
 * Used primarily to login to Drupal sites powered by oauth2_server or PHP
 * sites powered by oauth2-server-php.
 */

/*
 * There is no good way to test whether an 'include' will succeed, so
 * temporarily set a null error handler to avoid warnings which will
 * confuse end users.
 */
set_error_handler(function() { });
include 'Crypt/RSA.php';
restore_error_handler();

class OpenIDConnectClientGeneric extends OpenIDConnectClientBase {

  /**
   * Per RFC4648, "base64 encoding with URL-safe and filename-safe
   * alphabet".  This just replaces characters 62 and 63.  None of the
   * reference implementations seem to restore the padding if necessary,
   * but we'll do it anyway.
   *
   */
  protected function b64url2b64($base64url) {
    // "Shouldn't" be necessary, but why not
    $padding = strlen($base64url) % 4;
    if ($padding > 0) {
      $base64url .= str_repeat("=", 4 - $padding);
    }
    return strtr($base64url, '-_', '+/');
  }

  protected function base64url_decode($base64url) {
    return base64_decode($this->b64url2b64($base64url));
  }

  /**
   * Overrides OpenIDConnectClientBase::settingsForm().
   */
  public function settingsForm() {
    $form = parent::settingsForm();

    $default_site = 'https://example.com/oauth2';
    $form['issuer_uri'] = array(
      '#title' => t('OpenID Connect issuer'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('issuer_uri', 'https://example.com'),
      '#description' => t("The base URI for your OpenID Connect server."),
    );

    $form['auto_config'] = array(
      '#title' => t('Fetch provider configuration automatically'),
      '#type' => 'checkbox',
      '#default_value' => $this->getSetting('auto_config', 1),
      '#description' => t("If checked, the values below will be populated automatically, if the server supports it."),
    );

    $form['verify_jwt'] = array(
      '#title' => t('Verify token signatures'),
      '#type' => 'checkbox',
      '#default_value' => $this->getSetting('verify_jwt', 1),
      '#description' => t("If unchecked, you are vulnerable to man-in-the-middle attacks"),
    );

    $form['authorization_endpoint'] = array(
      '#title' => t('Authorization endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('authorization_endpoint', $default_site . '/authorize'),
    );
    $form['token_endpoint'] = array(
      '#title' => t('Token endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('token_endpoint', $default_site . '/token'),
    );
    $form['userinfo_endpoint'] = array(
      '#title' => t('UserInfo endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('userinfo_endpoint', $default_site . '/userinfo'),
    );

    $form['jwks_uri'] = array(
      '#title' => t('JWK URI'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('jwks_uri', $default_site . '/jwk'),
    );

    return $form;
  }

  /**
   * Overrides OpenIDConnectClientBase::settingsFormValidate().
   */
  public function settingsFormValidate($form, &$form_state, $error_element_base) {
    if (!$form_state['values']['verify_jwt']) {
      drupal_set_message(t('Warning: By disabling id token verification, you are leaving yourself vulnerable to man-in-the-middle attacks'), 'warning');
    } elseif (!class_exists('Crypt_RSA')) {
      form_set_error('verify_jwt', 'Crypt/RSA unavailable.  Cannot verify token signatures.');
    }
  }

  /**
   * Overrides OpenIDConnectClientBase::settingsFormSubmit().
   */
  public function settingsFormSubmit($form, &$form_state) {
    $issuer_uri = $form_state['values']['issuer_uri'];
    /* Ensure it ends in a slash */
    $issuer_uri = trim($issuer_uri, '/') . '/';
    $form_state['values']['issuer_uri'] = $issuer_uri;
    $cfg_uri = $issuer_uri . '.well-known/openid-configuration';
    if ($form_state['values']['auto_config']) {
      $response = drupal_http_request($cfg_uri,
                                      array('timeout' => '10'));
      if (!isset($response->error) && $response->code == 200) {
        $response_data = drupal_json_decode($response->data);
        $form_state['values']['authorization_endpoint'] = $response_data['authorization_endpoint'];
        $form_state['values']['token_endpoint'] = $response_data['token_endpoint'];
        $form_state['values']['userinfo_endpoint'] = $response_data['userinfo_endpoint'];
        $form_state['values']['jwks_uri'] = $response_data['jwks_uri'];
      } else {
        form_set_error('issuer_uri', 'Unable to populate values automatically: ' . $response->error);
        $form_state['values']['auto_config'] = 0;
      }
    }
  }

  private function log_jwt_error($msg) {
    watchdog('openid_connect_client_' . $this->name,
             'Token verification error: @err',
             array('@err' => $msg), WATCHDOG_ERROR);
  }

  /**
   * Overrides OpenIDConnectClientBase::retieveTokens().
   */
  public function retrieveTokens($authorization_code) {
    $tokens = parent::retrieveTokens($authorization_code);
    if (! $this->settings['verify_jwt']) {
      return $tokens;
    }
    if ($tokens) {
      if (!class_exists('Crypt_RSA')) {
        $this->log_jwt_error('Crypt_RSA unavailable, cannot verify signatures');
        return FALSE;
      }
      $tokenparts = explode('.', $tokens['id_token']);
      list($header, $body, $sig) = array_map(array($this, 'base64url_decode'),
                                             $tokenparts);
      $header = drupal_json_decode($header);
      $body = drupal_json_decode($body);
      $matches = array();
      if (! preg_match('/^RS(\d+)$/', $header['alg'], $matches)) {
        $this->log_jwt_error('Unknown key signature type: ' + $header['alg']);
        return FALSE;
      }
      $hashtype = 'sha' . $matches[1];
      $response = drupal_http_request($this->settings['jwks_uri'],
                                      array('timeout' => '10'));
      if (isset($response->error) || ($response->code != 200)) {
        $this->log_jwt_error('Failed to retrieve JWK URI: ' + $response->error);
        return FALSE;
      }
      $jwks = drupal_json_decode($response->data);
      $pubkey = NULL;
      foreach ($jwks['keys'] as $key) {
        if ($key['kty'] == 'RSA') {
          $pubkey = $key;
          break;
        }
      }
      if (is_null($pubkey)) {
        $this->log_jwt_error('Unable to find an RSA public key');
        return FALSE;
      }
      $public_key_xml = "<RSAKeyValue>\r\n".
        "  <Modulus>" . $this->b64url2b64($pubkey['n']) . "</Modulus>\r\n" .
        "  <Exponent>" . $this->b64url2b64($pubkey['e']) . "</Exponent>\r\n" .
        "</RSAKeyValue>";
      $rsa = new Crypt_RSA();
      $rsa->setHash($hashtype);
      $rsa->loadKey($public_key_xml, CRYPT_RSA_PUBLIC_FORMAT_XML);
      // PKCS1.5, despite the constant name
      $rsa->signatureMode = CRYPT_RSA_SIGNATURE_PKCS1;
      if (! $rsa->verify($tokenparts[0] . '.' . $tokenparts[1],
                         $sig)) {
        $this->log_jwt_error('Signature verification failed!');
        return FALSE;
      }
    }
    return $tokens;
  }


  /**
   * Overrides OpenIDConnectClientBase::getEndpoints().
   */
  public function getEndpoints() {
    return array(
      'authorization' => $this->getSetting('authorization_endpoint'),
      'token' => $this->getSetting('token_endpoint'),
      'userinfo' => $this->getSetting('userinfo_endpoint'),
    );
  }
}
