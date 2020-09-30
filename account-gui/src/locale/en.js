import I18n from "i18n-js";

I18n.translations.en = {
    login: {
        requestEduId: "No eduID?",
        requestEduId2: "Request one!",
        loginEduId: "Login!",
        whatis: "What is eduID?",
        header: "Sign in with eduID",
        headerSubTitle: "to continue to ",
        header2: "Request your eduID",
        trust: "Trust this computer",
        loginOptions: "Other sign-in options",
        loginOptionsToolTip: "The sign-in options are managed in your eduID.",
        email: "Your email address",
        emailPlaceholder: "Email, e.g. user@gmail.com",
        passwordPlaceholder: "Password",
        familyName: "Last name",
        givenName: "First name",
        familyNamePlaceholder: "Last name, e.g. Berners-Lee",
        givenNamePlaceholder: "First name, e.g. Tim",
        sendMagicLink: "Email a magic link",
        loginWebAuthn: "Login with security key",
        usePassword: "type a password.",
        useMagicLink: "Email a magic link",
        useWebAuth: "Sign in with a security key",
        useOr: "or",
        requestEduIdButton: "Request your eduID",
        rememberMe: "Stay logged in",
        password: "Your password",
        passwordForgotten: "Forgot your password or prefer a magic link? ",
        passwordForgottenLink: "Receive an email to sign in instantly.",
        login: "Login",
        create: "Create",
        newTo: "New to eduID?",
        createAccount: " Create an account.",
        useExistingAccount: "Use existing account",
        invalidEmail: "Invalid email",
        requiredAttribute: "{{attr}} is required",
        emailInUse: "Email is already in use.",
        emailNotFound: "Email not found.",
        emailOrPasswordIncorrect: "Email or password are incorrect",
        institutionDomainNameWarning: "It looks like you entered an institutional email address. Please note that when you no longer study at or work for that institution, you can no longer use that email address.",
        institutionDomainNameWarning2: "We recommend using your personal email address for eduID.",
        passwordDisclaimer: "Make sure it's at least 15 characters long OR at least 8 characters when including a number and an UpperCase letter.",
        alreadyGuestAccount: "Already have an eduID?",
        usePasswordLink: "Type a password anyway",
        useWebAuthnLink: "Or use WebAuthn",
        agreeWithTerms: "<span>I agree with <a href='https://eduid.nl/terms_of_service/' target='_blank'>the terms of service.</a> I also understand <a href='https://eduid.nl/privacy_policy/' target='_blank'>the privacy policy</a>.</span>"
    },
    magicLink: {
        header: "Please",
        header2: "Check your email",
        info1: "We've sent you an email at",
        info2: "It contains a magic link that will sign you in.",
        wrongEmail: "Is the above email address incorrect?",
        wrongEmail2: "Please start over."
    },
    confirm: {
        header: "Success!",
        thanks: "Your eduID account has been created. Proceed to your destination.",
    },
    confirmStepup: {
        header: "Thanks!",
        proceed: "Go to {{name}}",
        conditionMet: "All conditions are met."
    },
    stepup: {
        header: "One more thing!",
        info: "To proceed to <strong> {{name}} </strong>, you must meet the following condition(s).",
        link: "Verify this via SURFconext"
    },
    footer: {
        privacy: "Privacy policy",
        terms: "Terms of Use",
        help: "Help",
        poweredBy: "Powered by"
    },
    session: {
        title: "Your session was lost.",
        info: "You must open the magic link from the email in the same browser session as where you requested the magic link. <br/><br/>  Please go back to the service you were heading to and request a new magic link."
    },
    expired: {
        title: "Expired magic link",
        info: "The magic link you have used is either expired or has already been used.",
        back: "Go to eduid.nl"
    },
    notFound: {
        title: "Whoops...",
        title2: "Something went wrong (404)"
    },
    webAuthn: {
        info: "Enable Public Key Cryptography and Web Authentication (WebAuthn)",
        browserPrompt: "Your browser is prompting you to register one of your security keys or fingerprint with your account"
    },
    migration: {
        header: "Migrate to an <br/>eduID guest account",
        info1: "SURF will phase out the use of Onegini. To retain access, you must migrate your Onegini account to an eduID account.",
        info2: "You only need to click the button and log in with your existing Onegini account once. We will then migrate your account to eduID and send you an email after completion.",
        link: "Start migration"
    },
    affiliationMissing: {
        header: "Account linked, but...",
        info: "Your eduID is successfully linked, however the institution you choose did not provide the correct affiliation.",
        proceed: "You can try to link to another institution or proceed to {{name}}",
        proceedLink: "Proceed",
        retryLink: "Retry"
    },
    validNameMissing: {
        header: "Account linked, but...",
        info: "Your eduID is successfully linked, however the institution you choose did not provide a valid name.",
        proceed: "You can try to link to another institution or proceed to {{name}}",
        proceedLink: "Proceed",
        retryLink: "Retry"
    },
    stepUpExplanation: {
        linked_institution: "Your eduID account must be linked to a trusted party.",
        validate_names: "Your first name and last name must be verified by a trusted party.",
        affiliation_student: "You must prove that you are following education by linking your eduID account to a trusted party."
    },
    stepUpVerification: {
        linked_institution: "Your eduID account is linked to a trusted party.",
        validate_names: "Your first name and last name are verified by a trusted party.",
        affiliation_student: "You have proven that you are following education by linking your eduID account to a trusted party.."
    }

};
