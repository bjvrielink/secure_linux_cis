# A description of what this class does
#
# Description:
# The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm).
# All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.
#
# Rationale:
# The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection
# to the system by increasing the level of effort for an attacker to successfully determine passwords.
#
# Note that these change only apply to accounts configured on the local system.
#
# @summary A short summary of the purpose of this class
#
# @param enforced Should this rule be enforced
#
# @example
#   include secure_linux_cis::debian9::cis_5_3_4
class secure_linux_cis::debian9::cis_5_3_4  (
  Boolean $enforced = true,
) {

  $services = [
    'common-password',
  ]

  if $enforced {

    $services.each | $service | {

      pam { "pam_unix ${service}":
        ensure           => present,
        service          => $service,
        type             => 'password',
        module           => 'pam_unix.so',
        control          => '[success=1 default=ignore]',
        control_is_param => true,
        arguments        => [
          'obscure',
          'use_authtok',
          'try_first_pass',
          'sha512',
        ],
      }

    }
  }
}
