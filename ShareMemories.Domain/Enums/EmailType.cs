using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ShareMemories.Domain.Enums
{
    public enum EmailType
    {
        ConfirmationEmail,
        PasswordReset,
        TwoFactorAuthenticationLogin,
        TwoFactorAuthenticationEnabled,
        TwoFactorAuthenticationDisabled,
        UnlocKAccountRequested,
        UnlocKAccount,
        DetailsUpdated
    }
}
