# 5.3.2 Ensure lockout for failed password attempts is configured (Scored)
#
# Description:
# Lock out users after n unsuccessful consecutive login attempts. The first sets of changes are made to the PAM configuration files. The
# second set of changes are applied to the program specific PAM configuration file. The second set of changes must be applied to each
# program that will lock out users. Check the documentation for each secondary program for instructions on how to configure them to work
# with PAM.
#
# Set the lockout number to the policy in effect at your site.
#
# Rationale:
# Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
#
# @summary 5.3.2 Ensure lockout for failed password attempts is configured (Scored)
#
# @param enforced Should this rule be enforced
# @param attempts Number of attempts
# @param lockout_time Amount of time for lockout
#
# @example
#   include secure_linux_cis::debian9::cis_5_3_2
class secure_linux_cis::debian9::cis_5_3_2 (
  Boolean $enforced = true,
  Integer $attempts = 5,
  Integer $lockout_time = 900,
) {

  $services = [
    'common-auth',
  ]

  if $enforced {

    $services.each | $service | {

      pam { "pam_tally2 ${service}":
        ensure    => present,
        service   => $service,
        type      => 'auth',
        module    => 'pam_tally2.so',
        control   => 'required',
        arguments => [
          'onerr=fail',
          'audit',
          'silent',
          "deny=${attempts}",
          "unlock_time=${lockout_time}",
        ],
        position  => 'before *[type="auth" and module="pam_unix.so"]',
      }

    }
  }
}
