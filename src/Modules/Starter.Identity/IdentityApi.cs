using System.Data.Common;
using Microsoft.EntityFrameworkCore.Storage;
using Starter.Identity.ChangePassword;
using Starter.Identity.GoogleSignIn;
using Starter.Identity.Login;
using Starter.Identity.PasswordReset;
using Starter.Identity.Refresh;
using Starter.Identity.Register;
using Starter.Identity.SetPassword;
using Starter.Identity.Tokens;
using Starter.Identity.Verification;
using Starter.Platform.Auth;
using Starter.SharedKernel;

namespace Starter.Identity;

/// <summary>
/// The module facade: one internal class carrying the public interface,
/// delegating to the per-use-case slice handlers (LLD section 1 vertical
/// slices).
/// </summary>
internal sealed class IdentityApi(
    RegisterHandler register,
    LoginHandler login,
    RefreshHandler refresh,
    GoogleSignInHandler googleSignIn,
    SetPasswordHandler setPassword,
    ChangePasswordHandler changePassword,
    RequestPasswordResetHandler requestPasswordReset,
    ResetPasswordHandler resetPassword,
    VerifyEmailHandler verifyEmail,
    VerificationStatusHandler verificationStatus,
    ResendVerificationHandler resendVerification,
    VerifiedEmailQuery verifiedEmail,
    RegistrationStagingHandler registrationStaging,
    VerificationEmailComposer verificationEmail,
    IssueSessionForHandler issueSessionFor,
    SelectTenantHandler selectTenant) : IIdentityApi
{
    public Task<Result> RegisterAsync(string email, string password, CancellationToken cancellationToken) =>
        register.HandleAsync(email, password, cancellationToken);

    public Task<Result<IssuedTokens>> LoginAsync(
        string email,
        string password,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken) =>
        login.HandleAsync(email, password, deviceLabel, ipAddress, cancellationToken);

    public Task<Result<IssuedTokens>> RefreshAsync(
        string refreshToken,
        string? ipAddress,
        CancellationToken cancellationToken) =>
        refresh.HandleAsync(refreshToken, ipAddress, cancellationToken);

    public Task<Result<IssuedTokens>> SignInWithGoogleAsync(
        string code,
        string codeVerifier,
        string redirectUri,
        string nonce,
        Guid? confirmedUserId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken) =>
        googleSignIn.HandleAsync(
            code, codeVerifier, redirectUri, nonce, confirmedUserId, deviceLabel, ipAddress, cancellationToken);

    public Task<Result> SetPasswordAsync(Guid userId, string newPassword, CancellationToken cancellationToken) =>
        setPassword.HandleAsync(userId, newPassword, cancellationToken);

    public Task<Result> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken) =>
        changePassword.HandleAsync(userId, currentPassword, newPassword, cancellationToken);

    public Task<Result> RequestPasswordResetAsync(string email, CancellationToken cancellationToken) =>
        requestPasswordReset.HandleAsync(email, cancellationToken);

    public Task<Result> ResetPasswordAsync(string token, string newPassword, CancellationToken cancellationToken) =>
        resetPassword.HandleAsync(token, newPassword, cancellationToken);

    public Task<Result> VerifyEmailAsync(string token, CancellationToken cancellationToken) =>
        verifyEmail.HandleAsync(token, cancellationToken);

    public Task<Result<VerificationTokenStatus>> GetVerificationTokenStatusAsync(
        string token,
        CancellationToken cancellationToken) =>
        verificationStatus.HandleAsync(token, cancellationToken);

    public Task<Result> ResendVerificationEmailAsync(Guid userId, CancellationToken cancellationToken) =>
        resendVerification.HandleAsync(userId, cancellationToken);

    public Task<bool> IsEmailVerifiedAsync(Guid userId, CancellationToken cancellationToken) =>
        verifiedEmail.IsVerifiedAsync(userId, cancellationToken);

    public Task<Result<StagedRegistration>> StageRegistrationAsync(
        DbConnection sharedConnection,
        IDbContextTransaction sharedTransaction,
        string email,
        string password,
        CancellationToken cancellationToken) =>
        registrationStaging.HandleAsync(sharedConnection, sharedTransaction, email, password, cancellationToken);

    public Task SendVerificationEmailAsync(string email, string rawToken, CancellationToken cancellationToken) =>
        verificationEmail.SendVerificationEmailAsync(email, rawToken, cancellationToken);

    public Task<Result<IssuedTokens>> IssueSessionForAsync(
        Guid userId,
        Guid? tenantId,
        string? deviceLabel,
        string? ipAddress,
        CancellationToken cancellationToken) =>
        issueSessionFor.HandleAsync(userId, tenantId, deviceLabel, ipAddress, cancellationToken);

    public Task<Result<TenantAccessToken>> SelectTenantAsync(
        Guid userId,
        Guid sessionId,
        Guid tenantId,
        CancellationToken cancellationToken) =>
        selectTenant.HandleAsync(userId, sessionId, tenantId, cancellationToken);
}
