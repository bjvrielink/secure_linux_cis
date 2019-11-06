# 5.3.3 Ensure password reuse is limited (Scored)
#
# Description:
# The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.
#
# Rationale:
# Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password.
#
# Note that these change only apply to accounts configured on the local system.
#
# @summary 5.3.3 Ensure password reuse is limited (Scored)
#
# @param enforced Should this rule be enforced
# @param past_passwords Number of previous passwords
#
# @example
#   include secure_linux_cis::debian9::cis_5_3_3
class secure_linux_cis::debian9::cis_5_3_3 (
  Boolean $enforced = true,
  Integer $past_passwords = 5,
) {

  $services = [
    'common-password',
  ]

  if $enforced {

    if $past_passwords < 5 {
      fail('CIS recommends setting old password limit to previous 5.')
    }

    else {

      $services.each | $service | {

        pam { "pam ${service} pwhistory":
          ensure    => present,
          service   => $service,
          type      => 'password',
          control   => 'required',
          module    => 'pam_pwhistory.so',
          arguments => ["remember=${past_passwords}"],
          position  => 'before *[type="password" and module="pam_unix.so"]',
        }
      }
    }
  }
}
