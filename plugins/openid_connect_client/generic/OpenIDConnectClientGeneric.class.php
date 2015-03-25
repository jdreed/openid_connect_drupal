<?php

/**
 * @file
 * Generic OpenID Connect client.
 *
 * Used primarily to login to Drupal sites powered by oauth2_server or PHP
 * sites powered by oauth2-server-php.
 */

class OpenIDConnectClientGeneric extends OpenIDConnectClientBase {

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

    return $form;
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
      } else {
        form_set_error('issuer_uri', 'Unable to populate values automatically: ' . $response->error);
        $form_state['values']['auto_config'] = 0;
      }
    }
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
