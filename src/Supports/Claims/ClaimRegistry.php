<?php

namespace AlirezaMoh\JwtShield\Supports\Claims;

enum ClaimRegistry: string
{
    /**
     * Issuer claim.
     * Identifies the principal that issued the JWT.
     *
     * @var string
     */
    case ISS = 'iss';

    /**
     * Subject claim.
     * Identifies the principal that is the subject of the JWT.
     *
     * @var string
     */
    case SUB = 'sub';

    /**
     * Audience claim.
     * Identifies the recipients that the JWT is intended for.
     *
     * @var string
     */
    case AUD = 'aud';

    /**
     * Expiration Time claim.
     * Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
     *
     * @var string
     */
    case EXP = 'exp';

    /**
     * Not Before claim.
     * Identifies the time before which the JWT MUST NOT be accepted for processing.
     *
     * @var string
     */
    case NBF = 'nbf';

    /**
     * Issued At claim.
     * Identifies the time at which the JWT was issued.
     *
     * @var string
     */
    case IAT = 'iat';

    /**
     * JWT ID claim.
     * Provides a unique identifier for the JWT.
     *
     * @var string
     */
    case JTI = 'jti';

    /**
     * Full name claim.
     * Represents the full name of the End-User.
     *
     * @var string
     */
    case NAME = 'name';

    /**
     * Given name claim.
     * Represents the given name(s) or first name(s) of the End-User.
     *
     * @var string
     */
    case GIVEN_NAME = 'given_name';

    /**
     * Surname claim.
     * Represents the surname(s) or last name(s) of the End-User.
     *
     * @var string
     */
    case FAMILY_NAME = 'family_name';

    /**
     * Middle name claim.
     * Represents the middle name(s) of the End-User.
     *
     * @var string
     */
    case MIDDLE_NAME = 'middle_name';

    /**
     * Nickname claim.
     * Represents the casual name of the End-User.
     *
     * @var string
     */
    case NICKNAME = 'nickname';

    /**
     * Preferred username claim.
     * Represents the shorthand name by which the End-User wishes to be referred to.
     *
     * @var string
     */
    case PREFERRED_USERNAME = 'preferred_username';

    /**
     * Profile URL claim.
     * Represents the URL of the End-User's profile page.
     *
     * @var string
     */
    case PROFILE = 'profile';

    /**
     * Profile picture URL claim.
     * Represents the URL of the End-User's profile picture.
     *
     * @var string
     */
    case PICTURE = 'picture';

    /**
     * Website claim.
     * Represents the URL of the End-User's web page or blog.
     *
     * @var string
     */
    case WEBSITE = 'website';

    /**
     * Email claim.
     * Represents the preferred e-mail address of the End-User.
     *
     * @var string
     */
    case EMAIL = 'email';

    /**
     * Email verified claim.
     * Represents whether the e-mail address has been verified (true) or not (false).
     *
     * @var string
     */
    case EMAIL_VERIFIED = 'email_verified';

    /**
     * Gender claim.
     * Represents the gender of the End-User.
     *
     * @var string
     */
    case GENDER = 'gender';

    /**
     * Birthdate claim.
     * Represents the birthday of the End-User.
     *
     * @var string
     */
    case BIRTHDATE = 'birthdate';

    /**
     * Time zone claim.
     * Represents the time zone of the End-User.
     *
     * @var string
     */
    case ZONEINFO = 'zoneinfo';

    /**
     * Locale claim.
     * Represents the locale of the End-User.
     *
     * @var string
     */
    case LOCALE = 'locale';

    /**
     * Preferred telephone number claim.
     * Represents the preferred telephone number of the End-User.
     *
     * @var string
     */
    case PHONE_NUMBER = 'phone_number';

    /**
     * Phone number verified claim.
     * Represents whether the phone number has been verified (true) or not (false).
     *
     * @var string
     */
    case PHONE_NUMBER_VERIFIED = 'phone_number_verified';

    /**
     * Preferred postal address claim.
     * Represents the preferred postal address of the End-User.
     *
     * @var string
     */
    case ADDRESS = 'address';

    /**
     * Updated at claim.
     * Represents the time when the information was last updated.
     *
     * @var string
     */
    case UPDATED_AT = 'updated_at';

    /**
     * Authorized party claim.
     * Represents the party to which the ID Token was issued.
     *
     * @var string
     */
    case AZP = 'azp';

    /**
     * Nonce claim.
     * Represents a value used to associate a Client session with an ID Token.
     *
     * @var string
     */
    case NONCE = 'nonce';

    /**
     * Authentication time claim.
     * Represents the time when the authentication occurred.
     *
     * @var string
     */
    case AUTH_TIME = 'auth_time';

    /**
     * Access Token hash claim.
     * Represents the Access Token hash value.
     *
     * @var string
     */
    case AT_HASH = 'at_hash';

    /**
     * Code hash claim.
     * Represents the Code hash value.
     *
     * @var string
     */
    case C_HASH = 'c_hash';

    /**
     * Authentication Context Class Reference claim.
     * Represents the Authentication Context Class Reference.
     *
     * @var string
     */
    case ACR = 'acr';

    /**
     * Authentication Methods References claim.
     * Represents the Authentication Methods References.
     *
     * @var string
     */
    case AMR = 'amr';

    /**
     * Public key used to check the signature of an ID Token claim.
     * Represents the public key used to check the signature of an ID Token.
     *
     * @var string
     */
    case SUB_JWK = 'sub_jwk';

    /**
     * Confirmation claim.
     * Represents the confirmation claim.
     *
     * @var string
     */
    case CNF = 'cnf';

    /**
     * SIP From tag claim.
     * Represents the SIP From tag header field parameter value.
     *
     * @var string
     */
    case SIP_FROM_TAG = 'sip_from_tag';

    /**
     * SIP Date claim.
     * Represents the SIP Date header field value.
     *
     * @var string
     */
    case SIP_DATE = 'sip_date';

    /**
     * SIP Call-Id claim.
     * Represents the SIP Call-Id header field value.
     *
     * @var string
     */
    case SIP_CALLID = 'sip_callid';

    /**
     * SIP CSeq numeric claim.
     * Represents the SIP CSeq numeric header field parameter value.
     *
     * @var string
     */
    case SIP_CSEQ_NUM = 'sip_cseq_num';

    /**
     * SIP Via branch claim.
     * Represents the SIP Via branch header field parameter value.
     *
     * @var string
     */
    case SIP_VIA_BRANCH = 'sip_via_branch';

    /**
     * Originating Identity String claim.
     * Represents the Originating Identity String.
     *
     * @var string
     */
    case ORIG = 'orig';

    /**
     * Destination Identity String claim.
     * Represents the Destination Identity String.
     *
     * @var string
     */
    case DEST = 'dest';

    /**
     * Media Key Fingerprint String claim.
     * Represents the Media Key Fingerprint String.
     *
     * @var string
     */
    case MKY = 'mky';

    /**
     * Security Events claim.
     * Represents the Security Events.
     *
     * @var string
     */
    case EVENTS = 'events';

    /**
     * Time of Event claim.
     * Represents the Time of Event.
     *
     * @var string
     */
    case TOE = 'toe';

    /**
     * Transaction Identifier claim.
     * Represents the Transaction Identifier.
     *
     * @var string
     */
    case TXN = 'txn';

    /**
     * Resource Priority Header Authorization claim.
     * Represents the Resource Priority Header Authorization.
     *
     * @var string
     */
    case RPH = 'rph';

    /**
     * Session ID claim.
     * Represents the Session ID.
     *
     * @var string
     */
    case SID = 'sid';

    /**
     * Vector of Trust value claim.
     * Represents the Vector of Trust value.
     *
     * @var string
     */
    case VOT = 'vot';

    /**
     * Vector of Trust trustmark URL claim.
     * Represents the Vector of Trust trustmark URL.
     *
     * @var string
     */
    case VTM = 'vtm';

    /**
     * Attestation level claim as defined in the SHAKEN framework.
     * Represents the Attestation level as defined in the SHAKEN framework.
     *
     * @var string
     */
    case ATTEST = 'attest';

    /**
     * Originating Identifier claim as defined in the SHAKEN framework.
     * Represents the Originating Identifier as defined in the SHAKEN framework.
     *
     * @var string
     */
    case ORIGID = 'origid';

    /**
     * Actor claim.
     * Represents the Actor.
     *
     * @var string
     */
    case ACT = 'act';

    /**
     * Scope Values claim.
     * Represents the Scope Values.
     *
     * @var string
     */
    case SCOPE = 'scope';

    /**
     * Client Identifier claim.
     * Represents the Client Identifier.
     *
     * @var string
     */
    case CLIENT_ID = 'client_id';

    /**
     * Authorized Actor claim - the party that is authorized to become the actor.
     * Represents the Authorized Actor.
     *
     * @var string
     */
    case MAY_ACT = 'may_act';

    /**
     * jCard data claim.
     * Represents the jCard data.
     *
     * @var string
     */
    case JCARD = 'jcard';

    /**
     * Number of API requests claim for which the access token can be used.
     * Represents the Number of API requests for which the access token can be used.
     *
     * @var string
     */
    case AT_USE_NBR = 'at_use_nbr';

    /**
     * Diverted Target of a Call claim.
     * Represents the Diverted Target of a Call.
     *
     * @var string
     */
    case DIV = 'div';

    /**
     * Original PASSporT (in Full Form) claim.
     * Represents the Original PASSporT (in Full Form).
     *
     * @var string
     */
    case OPT = 'opt';

    /**
     * Verifiable Credential claim as specified in the W3C Recommendation.
     * Represents the Verifiable Credential as specified in the W3C Recommendation.
     *
     * @var string
     */
    case VC = 'vc';

    /**
     * Verifiable Presentation claim as specified in the W3C Recommendation.
     * Represents the Verifiable Presentation as specified in the W3C Recommendation.
     *
     * @var string
     */
    case VP = 'vp';

    /**
     * SIP Priority header field claim.
     * Represents the SIP Priority header field.
     *
     * @var string
     */
    case SPH = 'sph';

    /**
     * The ACE profile a token is supposed to be used with claim.
     * Represents the ACE profile a token is supposed to be used with.
     *
     * @var string
     */
    case ACE_PROFILE = 'ace_profile';

    /**
     * "client-nonce". A nonce previously provided to the AS by the RS via the client claim.
     * Represents the "client-nonce" (cnonce).
     *
     * @var string
     */
    case CNONCE = 'cnonce';

    /**
     * "Expires in". Lifetime of the token in seconds from the time the RS first sees it claim.
     * Represents the "Expires in" (exi).
     *
     * @var string
     */
    case EXI = 'exi';

    /**
     * Roles claim.
     * Represents the Roles.
     *
     * @var string
     */
    case ROLES = 'roles';

    /**
     * Groups claim.
     * Represents the Groups.
     *
     * @var string
     */
    case GROUPS = 'groups';

    /**
     * Entitlements claim.
     * Represents the Entitlements.
     *
     * @var string
     */
    case ENTITLEMENTS = 'entitlements';

    /**
     * Token introspection response claim.
     * Represents the Token introspection response.
     *
     * @var string
     */
    case TOKEN_INTROSPECTION = 'token_introspection';

    /**
     * The Universal Entity ID claim.
     * Represents the Universal Entity ID.
     *
     * @var string
     */
    case UEID = 'ueid';

    /**
     * Semi-permanent UEIDs claim.
     * Represents the Semi-permanent UEIDs.
     *
     * @var string
     */
    case SUEIDS = 'sueids';

    /**
     * Hardware OEM ID claim.
     * Represents the Hardware OEM ID.
     *
     * @var string
     */
    case OEMID = 'oemid';

    /**
     * Model identifier for hardware claim.
     * Represents the Model identifier for hardware.
     *
     * @var string
     */
    case HWMODEL = 'hwmodel';

    /**
     * Hardware Version Identifier claim.
     * Represents the Hardware Version Identifier.
     *
     * @var string
     */
    case HWVERSION = 'hwversion';

    /**
     * Indicate whether the boot was secure claim.
     * Represents whether the boot was secure.
     *
     * @var string
     */
    case SECBOOT = 'secboot';

    /**
     * Indicate status of debug facilities claim.
     * Represents the status of debug facilities.
     *
     * @var string
     */
    case DBGSTAT = 'dbgstat';

    /**
     * The geographic location claim.
     * Represents the geographic location.
     *
     * @var string
     */
    case LOCATION = 'location';

    /**
     * Indicates the EAT profile followed claim.
     * Represents the EAT profile followed.
     *
     * @var string
     */
    case EAT_PROFILE = 'eat_profile';

    /**
     * The section containing submodules claim.
     * Represents the section containing submodules.
     *
     * @var string
     */
    case SUBMODS = 'submods';

    /**
     * CDNI Claim Set Version claim.
     * Represents the CDNI Claim Set Version.
     *
     * @var string
     */
    case CDNIV = 'cdniv';

    /**
     * CDNI Critical Claims Set claim.
     * Represents the CDNI Critical Claims Set.
     *
     * @var string
     */
    case CDNICRIT = 'cdnicrit';

    /**
     * CDNI IP Address claim.
     * Represents the CDNI IP Address.
     *
     * @var string
     */
    case CDNIIP = 'cdniip';

    /**
     * CDNI URI Container claim.
     * Represents the CDNI URI Container.
     *
     * @var string
     */
    case CDNIUC = 'cdniuc';

    /**
     * CDNI Expiration Time Setting for Signed Token Renewal claim.
     * Represents the CDNI Expiration Time Setting for Signed Token Renewal.
     *
     * @var string
     */
    case CDNIETS = 'cdniets';

    /**
     * CDNI Signed Token Transport Method for Signed Token Renewal claim.
     * Represents the CDNI Signed Token Transport Method for Signed Token Renewal.
     *
     * @var string
     */
    case CDNISTT = 'cdnistt';

    /**
     * CDNI Signed Token Depth claim.
     * Represents the CDNI Signed Token Depth.
     *
     * @var string
     */
    case CDNISTD = 'cdnistd';

    /**
     * Signed Content (with claims) claim.
     * Represents the Signed Content (with claims).
     *
     * @var string
     */
    case SIG_VAL_CLAIMS = 'sig_val_claims';

    /**
     * Authorization details associated with the entity claim.
     * Represents the authorization details associated with the entity.
     *
     * @var string
     */
    case AUTHORIZATION_DETAILS = 'authorization_details';

    /**
     * Claims that have been verified and are not needed for verification claim.
     * Represents claims that have been verified and are not needed for verification.
     *
     * @var string
     */
    case VERIFIED_CLAIMS = 'verified_claims';

    /**
     * Place of birth claim.
     * Represents the place of birth.
     *
     * @var string
     */
    case PLACE_OF_BIRTH = 'place_of_birth';

    /**
     * Nationalities or citizenships held claim.
     * Represents the nationalities or citizenships held.
     *
     * @var string
     */
    case NATIONALITIES = 'nationalities';

    /**
     * Family name at birth claim.
     * Represents the family name at birth.
     *
     * @var string
     */
    case BIRTH_FAMILY_NAME = 'birth_family_name';

    /**
     * Given name at birth claim.
     * Represents the given name at birth.
     *
     * @var string
     */
    case BIRTH_GIVEN_NAME = 'birth_given_name';

    /**
     * Middle name at birth claim.
     * Represents the middle name at birth.
     *
     * @var string
     */
    case BIRTH_MIDDLE_NAME = 'birth_middle_name';

    /**
     * Salutation claim.
     * Represents the salutation.
     *
     * @var string
     */
    case SALUTATION = 'salutation';

    /**
     * Title claim.
     * Represents the title.
     *
     * @var string
     */
    case TITLE = 'title';

    /**
     * Mobile Subscriber Integrated Services Digital Network Number claim.
     * Represents the Mobile Subscriber Integrated Services Digital Network Number (MSISDN).
     *
     * @var string
     */
    case MSISDN = 'msisdn';

    /**
     * Any other names by which the End-User may be known claim.
     * Represents any other names by which the End-User may be known.
     *
     * @var string
     */
    case ALSO_KNOWN_AS = 'also_known_as';

    /**
     * HTTP Transfer Method claim.
     * Represents the HTTP Transfer Method.
     *
     * @var string
     */
    case HTM = 'htm';

    /**
     * HTTP Transfer URI claim.
     * Represents the HTTP Transfer URI.
     *
     * @var string
     */
    case HTU = 'htu';

    /**
     * HTTP Authorization Header claim.
     * Represents the HTTP Authorization Header.
     *
     * @var string
     */
    case ATH = 'ath';

    /**
     * HTTP Authentication Credential claim.
     * Represents the HTTP Authentication Credential.
     *
     * @var string
     */
    case ATC = 'atc';

    /**
     * Subscriber Identifier claim.
     * Represents the Subscriber Identifier.
     *
     * @var string
     */
    case SUB_ID = 'sub_id';

    /**
     * Required claims data claim.
     * Represents the Required claims data.
     *
     * @var string
     */
    case RCD = 'rcd';

    /**
     * Required claims data interface claim.
     * Represents the Required claims data interface.
     *
     * @var string
     */
    case RCDI = 'rcdi';

    /**
     * Credential Identifier claim.
     * Represents the Credential Identifier.
     *
     * @var string
     */
    case CRN = 'crn';

    /**
     * Checks if the claim is the Issuer claim.
     *
     * @return bool True if the claim is the Issuer, false otherwise.
     */
    public function isIssuer(): bool
    {
        return $this === self::ISS;
    }

    /**
     * Checks if the claim is the Subject claim.
     *
     * @return bool True if the claim is the Subject, false otherwise.
     */
    public function isSubject(): bool
    {
        return $this === self::SUB;
    }

    /**
     * Checks if the claim is the Audience claim.
     *
     * @return bool True if the claim is the Audience, false otherwise.
     */
    public function isAudience(): bool
    {
        return $this === self::AUD;
    }

    /**
     * Checks if the claim is the Expiration Time claim.
     *
     * @return bool True if the claim is the Expiration Time, false otherwise.
     */
    public function isExpirationTime(): bool
    {
        return $this === self::EXP;
    }

    /**
     * Checks if the claim is the Not Before claim.
     *
     * @return bool True if the claim is the Not Before, false otherwise.
     */
    public function isNotBefore(): bool
    {
        return $this === self::NBF;
    }

    /**
     * Checks if the claim is the Issued At claim.
     *
     * @return bool True if the claim is the Issued At, false otherwise.
     */
    public function isIssuedAt(): bool
    {
        return $this === self::IAT;
    }

    /**
     * Checks if the claim is the JWT ID claim.
     *
     * @return bool True if the claim is the JWT ID, false otherwise.
     */
    public function isJWTID(): bool
    {
        return $this === self::JTI;
    }

    /**
     * Checks if the claim is the Full name claim.
     *
     * @return bool True if the claim is the Full name, false otherwise.
     */
    public function isFullName(): bool
    {
        return $this === self::NAME;
    }

    /**
     * Checks if the claim is the Given name claim.
     *
     * @return bool True if the claim is the Given name, false otherwise.
     */
    public function isGivenName(): bool
    {
        return $this === self::GIVEN_NAME;
    }

    /**
     * Checks if the claim is the Surname claim.
     *
     * @return bool True if the claim is the Surname, false otherwise.
     */
    public function isSurname(): bool
    {
        return $this === self::FAMILY_NAME;
    }

    /**
     * Checks if the claim is the Middle name claim.
     *
     * @return bool True if the claim is the Middle name, false otherwise.
     */
    public function isMiddleName(): bool
    {
        return $this === self::MIDDLE_NAME;
    }

    /**
     * Checks if the claim is the Nickname claim.
     *
     * @return bool True if the claim is the Nickname, false otherwise.
     */
    public function isNickname(): bool
    {
        return $this === self::NICKNAME;
    }

    /**
     * Checks if the claim is the Preferred username claim.
     *
     * @return bool True if the claim is the Preferred username, false otherwise.
     */
    public function isPreferredUsername(): bool
    {
        return $this === self::PREFERRED_USERNAME;
    }

    /**
     * Checks if the claim is the Profile URL claim.
     *
     * @return bool True if the claim is the Profile URL, false otherwise.
     */
    public function isProfile(): bool
    {
        return $this === self::PROFILE;
    }

    /**
     * Checks if the claim is the Profile picture URL claim.
     *
     * @return bool True if the claim is the Profile picture URL, false otherwise.
     */
    public function isPicture(): bool
    {
        return $this === self::PICTURE;
    }

    /**
     * Checks if the claim is the Website claim.
     *
     * @return bool True if the claim is the Website, false otherwise.
     */
    public function isWebsite(): bool
    {
        return $this === self::WEBSITE;
    }

    /**
     * Checks if the claim is the Email claim.
     *
     * @return bool True if the claim is the Email, false otherwise.
     */
    public function isEmail(): bool
    {
        return $this === self::EMAIL;
    }

    /**
     * Checks if the claim is the Email verified claim.
     *
     * @return bool True if the claim is the Email verified, false otherwise.
     */
    public function isEmailVerified(): bool
    {
        return $this === self::EMAIL_VERIFIED;
    }

    /**
     * Checks if the claim is the Gender claim.
     *
     * @return bool True if the claim is the Gender, false otherwise.
     */
    public function isGender(): bool
    {
        return $this === self::GENDER;
    }

    /**
     * Checks if the claim is the Birthdate claim.
     *
     * @return bool True if the claim is the Birthdate, false otherwise.
     */
    public function isBirthdate(): bool
    {
        return $this === self::BIRTHDATE;
    }

    /**
     * Checks if the claim is the Time zone claim.
     *
     * @return bool True if the claim is the Time zone, false otherwise.
     */
    public function isZoneInfo(): bool
    {
        return $this === self::ZONEINFO;
    }

    /**
     * Checks if the claim is the Locale claim.
     *
     * @return bool True if the claim is the Locale, false otherwise.
     */
    public function isLocale(): bool
    {
        return $this === self::LOCALE;
    }

    /**
     * Checks if the claim is the Preferred telephone number claim.
     *
     * @return bool True if the claim is the Preferred telephone number, false otherwise.
     */
    public function isPhoneNumber(): bool
    {
        return $this === self::PHONE_NUMBER;
    }

    /**
     * Checks if the claim is the Phone number verified claim.
     *
     * @return bool True if the claim is the Phone number verified, false otherwise.
     */
    public function isPhoneNumberVerified(): bool
    {
        return $this === self::PHONE_NUMBER_VERIFIED;
    }

    /**
     * Checks if the claim is the Preferred postal address claim.
     *
     * @return bool True if the claim is the Preferred postal address, false otherwise.
     */
    public function isAddress(): bool
    {
        return $this === self::ADDRESS;
    }

    /**
     * Checks if the claim is the Updated at claim.
     *
     * @return bool True if the claim is the Updated at, false otherwise.
     */
    public function isUpdatedAt(): bool
    {
        return $this === self::UPDATED_AT;
    }

    /**
     * Checks if the claim is the Authorized party claim.
     *
     * @return bool True if the claim is the Authorized party, false otherwise.
     */
    public function isAuthorizedParty(): bool
    {
        return $this === self::AZP;
    }

    /**
     * Checks if the claim is the Nonce claim.
     *
     * @return bool True if the claim is the Nonce, false otherwise.
     */
    public function isNonce(): bool
    {
        return $this === self::NONCE;
    }

    /**
     * Checks if the claim is the Authentication time claim.
     *
     * @return bool True if the claim is the Authentication time, false otherwise.
     */
    public function isAuthTime(): bool
    {
        return $this === self::AUTH_TIME;
    }

    /**
     * Checks if the claim is the Access Token hash claim.
     *
     * @return bool True if the claim is the Access Token hash, false otherwise.
     */
    public function isAccessTokenHash(): bool
    {
        return $this === self::AT_HASH;
    }

    /**
     * Checks if the claim is the Code hash claim.
     *
     * @return bool True if the claim is the Code hash, false otherwise.
     */
    public function isCodeHash(): bool
    {
        return $this === self::C_HASH;
    }

    /**
     * Checks if the claim is the Authentication Context Class Reference claim.
     *
     * @return bool True if the claim is the Authentication Context Class Reference, false otherwise.
     */
    public function isAcr(): bool
    {
        return $this === self::ACR;
    }

    /**
     * Checks if the claim is the Authentication Methods References claim.
     *
     * @return bool True if the claim is the Authentication Methods References, false otherwise.
     */
    public function isAmr(): bool
    {
        return $this === self::AMR;
    }

    /**
     * Checks if the claim is the Public key used to check the signature of an ID Token claim.
     *
     * @return bool True if the claim is the Public key used to check the signature of an ID Token, false otherwise.
     */
    public function isSubJWK(): bool
    {
        return $this === self::SUB_JWK;
    }

    /**
     * Checks if the claim is the Confirmation claim.
     *
     * @return bool True if the claim is the Confirmation, false otherwise.
     */
    public function isCnf(): bool
    {
        return $this === self::CNF;
    }

    /**
     * Checks if the claim is the SIP From tag claim.
     *
     * @return bool True if the claim is the SIP From tag, false otherwise.
     */
    public function isSipFromTag(): bool
    {
        return $this === self::SIP_FROM_TAG;
    }

    /**
     * Checks if the claim is the SIP Date claim.
     *
     * @return bool True if the claim is the SIP Date, false otherwise.
     */
    public function isSipDate(): bool
    {
        return $this === self::SIP_DATE;
    }

    /**
     * Checks if the claim is the SIP Call-Id claim.
     *
     * @return bool True if the claim is the SIP Call-Id, false otherwise.
     */
    public function isSipCallId(): bool
    {
        return $this === self::SIP_CALLID;
    }

    /**
     * Checks if the claim is the SIP CSeq numeric claim.
     *
     * @return bool True if the claim is the SIP CSeq numeric, false otherwise.
     */
    public function isSipCSeqNum(): bool
    {
        return $this === self::SIP_CSEQ_NUM;
    }

    /**
     * Checks if the claim is the SIP Via branch claim.
     *
     * @return bool True if the claim is the SIP Via branch, false otherwise.
     */
    public function isSipViaBranch(): bool
    {
        return $this === self::SIP_VIA_BRANCH;
    }

    /**
     * Checks if the claim is the Originating Identity String claim.
     *
     * @return bool True if the claim is the Originating Identity String, false otherwise.
     */
    public function isOrig(): bool
    {
        return $this === self::ORIG;
    }

    /**
     * Checks if the claim is the Destination Identity String claim.
     *
     * @return bool True if the claim is the Destination Identity String, false otherwise.
     */
    public function isDest(): bool
    {
        return $this === self::DEST;
    }

    /**
     * Checks if the claim is the Media Key Fingerprint String claim.
     *
     * @return bool True if the claim is the Media Key Fingerprint String, false otherwise.
     */
    public function isMky(): bool
    {
        return $this === self::MKY;
    }

    /**
     * Checks if the claim is the Security Events claim.
     *
     * @return bool True if the claim is the Security Events, false otherwise.
     */
    public function isEvents(): bool
    {
        return $this === self::EVENTS;
    }

    /**
     * Checks if the claim is the Time of Event claim.
     *
     * @return bool True if the claim is the Time of Event, false otherwise.
     */
    public function isToe(): bool
    {
        return $this === self::TOE;
    }

    /**
     * Checks if the claim is the Transaction Identifier claim.
     *
     * @return bool True if the claim is the Transaction Identifier, false otherwise.
     */
    public function isTxn(): bool
    {
        return $this === self::TXN;
    }

    /**
     * Checks if the claim is the Resource Priority Header Authorization claim.
     *
     * @return bool True if the claim is the Resource Priority Header Authorization, false otherwise.
     */
    public function isRph(): bool
    {
        return $this === self::RPH;
    }

    /**
     * Checks if the claim is the Session ID claim.
     *
     * @return bool True if the claim is the Session ID, false otherwise.
     */
    public function isSid(): bool
    {
        return $this === self::SID;
    }

    /**
     * Checks if the claim is the Vector of Trust value claim.
     *
     * @return bool True if the claim is the Vector of Trust value, false otherwise.
     */
    public function isVot(): bool
    {
        return $this === self::VOT;
    }

    /**
     * Checks if the claim is the Vector of Trust trustmark URL claim.
     *
     * @return bool True if the claim is the Vector of Trust trustmark URL, false otherwise.
     */
    public function isVtm(): bool
    {
        return $this === self::VTM;
    }

    /**
     * Checks if the claim is the Attestation level claim as defined in the SHAKEN framework.
     *
     * @return bool True if the claim is the Attestation level, false otherwise.
     */
    public function isAttest(): bool
    {
        return $this === self::ATTEST;
    }

    /**
     * Checks if the claim is the Originating Identifier claim as defined in the SHAKEN framework.
     *
     * @return bool True if the claim is the Originating Identifier, false otherwise.
     */
    public function isOrigid(): bool
    {
        return $this === self::ORIGID;
    }

    /**
     * Checks if the claim is the Actor claim.
     *
     * @return bool True if the claim is the Actor, false otherwise.
     */
    public function isAct(): bool
    {
        return $this === self::ACT;
    }

    /**
     * Checks if the claim is the Scope Values claim.
     *
     * @return bool True if the claim is the Scope Values, false otherwise.
     */
    public function isScope(): bool
    {
        return $this === self::SCOPE;
    }

    /**
     * Checks if the claim is the Client Identifier claim.
     *
     * @return bool True if the claim is the Client Identifier, false otherwise.
     */
    public function isClientId(): bool
    {
        return $this === self::CLIENT_ID;
    }

    /**
     * Checks if the claim is the Authorized Actor claim.
     *
     * @return bool True if the claim is the Authorized Actor, false otherwise.
     */
    public function isMayAct(): bool
    {
        return $this === self::MAY_ACT;
    }

    /**
     * Checks if the claim is the jCard data claim.
     *
     * @return bool True if the claim is the jCard data, false otherwise.
     */
    public function isJcard(): bool
    {
        return $this === self::JCARD;
    }

    /**
     * Checks if the claim is the Number of API requests claim for which the access token can be used.
     *
     * @return bool True if the claim is the Number of API requests, false otherwise.
     */
    public function isAtUseNbr(): bool
    {
        return $this === self::AT_USE_NBR;
    }

    /**
     * Checks if the claim is the Diverted Target of a Call claim.
     *
     * @return bool True if the claim is the Diverted Target of a Call, false otherwise.
     */
    public function isDiv(): bool
    {
        return $this === self::DIV;
    }

    /**
     * Checks if the claim is the Original PASSporT (in Full Form) claim.
     *
     * @return bool True if the claim is the Original PASSporT (in Full Form), false otherwise.
     */
    public function isOpt(): bool
    {
        return $this === self::OPT;
    }

    /**
     * Checks if the claim is the Verifiable Credential claim as specified in the W3C Recommendation.
     *
     * @return bool True if the claim is the Verifiable Credential, false otherwise.
     */
    public function isVc(): bool
    {
        return $this === self::VC;
    }

    /**
     * Checks if the claim is the Verifiable Presentation claim as specified in the W3C Recommendation.
     *
     * @return bool True if the claim is the Verifiable Presentation, false otherwise.
     */
    public function isVp(): bool
    {
        return $this === self::VP;
    }

    /**
     * Checks if the claim is the SIP Priority header field claim.
     *
     * @return bool True if the claim is the SIP Priority header field, false otherwise.
     */
    public function isSph(): bool
    {
        return $this === self::SPH;
    }

    /**
     * Checks if the claim is the The ACE profile a token is supposed to be used with claim.
     *
     * @return bool True if the claim is the ACE profile, false otherwise.
     */
    public function isAceProfile(): bool
    {
        return $this === self::ACE_PROFILE;
    }

    /**
     * Checks if the claim is the "client-nonce". A nonce previously provided to the AS by the RS via the client claim.
     *
     * @return bool True if the claim is the "client-nonce", false otherwise.
     */
    public function isCnonce(): bool
    {
        return $this === self::CNONCE;
    }

    /**
     * Checks if the claim is the "Expires in". Lifetime of the token in seconds from the time the RS first sees it claim.
     *
     * @return bool True if the claim is the "Expires in", false otherwise.
     */
    public function isExi(): bool
    {
        return $this === self::EXI;
    }

    /**
     * Checks if the claim is the Roles claim.
     *
     * @return bool True if the claim is the Roles, false otherwise.
     */
    public function isRoles(): bool
    {
        return $this === self::ROLES;
    }

    /**
     * Checks if the claim is the Groups claim.
     *
     * @return bool True if the claim is the Groups, false otherwise.
     */
    public function isGroups(): bool
    {
        return $this === self::GROUPS;
    }

    /**
     * Checks if the claim is the Entitlements claim.
     *
     * @return bool True if the claim is the Entitlements, false otherwise.
     */
    public function isEntitlements(): bool
    {
        return $this === self::ENTITLEMENTS;
    }

    /**
     * Checks if the claim is the Token introspection response claim.
     *
     * @return bool True if the claim is the Token introspection response, false otherwise.
     */
    public function isTokenIntrospection(): bool
    {
        return $this === self::TOKEN_INTROSPECTION;
    }

    /**
     * Checks if the claim is the The Universal Entity ID claim.
     *
     * @return bool True if the claim is the Universal Entity ID, false otherwise.
     */
    public function isUeid(): bool
    {
        return $this === self::UEID;
    }

    /**
     * Checks if the claim is the Semi-permanent UEIDs claim.
     *
     * @return bool True if the claim is the Semi-permanent UEIDs, false otherwise.
     */
    public function isSueids(): bool
    {
        return $this === self::SUEIDS;
    }

    /**
     * Checks if the claim is the Hardware OEM ID claim.
     *
     * @return bool True if the claim is the Hardware OEM ID, false otherwise.
     */
    public function isOemid(): bool
    {
        return $this === self::OEMID;
    }

    /**
     * Checks if the claim is the Model identifier for hardware claim.
     *
     * @return bool True if the claim is the Model identifier for hardware, false otherwise.
     */
    public function isHwmodel(): bool
    {
        return $this === self::HWMODEL;
    }

    /**
     * Checks if the claim is the Hardware Version Identifier claim.
     *
     * @return bool True if the claim is the Hardware Version Identifier, false otherwise.
     */
    public function isHwversion(): bool
    {
        return $this === self::HWVERSION;
    }

    /**
     * Checks if the claim is the Indicate whether the boot was secure claim.
     *
     * @return bool True if the claim is the Indicate whether the boot was secure, false otherwise.
     */
    public function isSecboot(): bool
    {
        return $this === self::SECBOOT;
    }

    /**
     * Checks if the claim is the Indicate status of debug facilities claim.
     *
     * @return bool True if the claim is the Indicate status of debug facilities, false otherwise.
     */
    public function isDbgstat(): bool
    {
        return $this === self::DBGSTAT;
    }

    /**
     * Checks if the claim is the The geographic location claim.
     *
     * @return bool True if the claim is the geographic location, false otherwise.
     */
    public function isLocation(): bool
    {
        return $this === self::LOCATION;
    }

    /**
     * Checks if the claim is the Indicates the EAT profile followed claim.
     *
     * @return bool True if the claim is the EAT profile followed, false otherwise.
     */
    public function isEatProfile(): bool
    {
        return $this === self::EAT_PROFILE;
    }

    /**
     * Checks if the claim is the section containing submodules claim.
     *
     * @return bool True if the claim is the section containing submodules, false otherwise.
     */
    public function isSubmods(): bool
    {
        return $this === self::SUBMODS;
    }

    /**
     * Checks if the claim is the CDNI Claim Set Version claim.
     *
     * @return bool True if the claim is the CDNI Claim Set Version, false otherwise.
     */
    public function isCdniv(): bool
    {
        return $this === self::CDNIV;
    }

    /**
     * Checks if the claim is the CDNI Critical Claims Set claim.
     *
     * @return bool True if the claim is the CDNI Critical Claims Set, false otherwise.
     */
    public function isCdnicrit(): bool
    {
        return $this === self::CDNICRIT;
    }

    /**
     * Checks if the claim is the CDNI IP Address claim.
     *
     * @return bool True if the claim is the CDNI IP Address, false otherwise.
     */
    public function isCdniip(): bool
    {
        return $this === self::CDNIIP;
    }

    /**
     * Checks if the claim is the CDNI URI Container claim.
     *
     * @return bool True if the claim is the CDNI URI Container, false otherwise.
     */
    public function isCdniuc(): bool
    {
        return $this === self::CDNIUC;
    }

    /**
     * Checks if the claim is the CDNI Expiration Time Setting for Signed Token Renewal claim.
     *
     * @return bool True if the claim is the CDNI Expiration Time Setting for Signed Token Renewal, false otherwise.
     */
    public function isCdniets(): bool
    {
        return $this === self::CDNIETS;
    }

    /**
     * Checks if the claim is the CDNI Signed Token Transport Method for Signed Token Renewal claim.
     *
     * @return bool True if the claim is the CDNI Signed Token Transport Method for Signed Token Renewal, false otherwise.
     */
    public function isCdnistt(): bool
    {
        return $this === self::CDNISTT;
    }

    /**
     * Checks if the claim is the CDNI Signed Token Depth claim.
     *
     * @return bool True if the claim is the CDNI Signed Token Depth, false otherwise.
     */
    public function isCdnistd(): bool
    {
        return $this === self::CDNISTD;
    }

    /**
     * Checks if the claim is the Signed Content (with claims) claim.
     *
     * @return bool True if the claim is the Signed Content (with claims), false otherwise.
     */
    public function isSigValClaims(): bool
    {
        return $this === self::SIG_VAL_CLAIMS;
    }

    /**
     * Checks if the claim is the Authorization details associated with the entity claim.
     *
     * @return bool True if the claim is the Authorization details associated with the entity, false otherwise.
     */
    public function isAuthorizationDetails(): bool
    {
        return $this === self::AUTHORIZATION_DETAILS;
    }

    /**
     * Checks if the claim is the Claims that have been verified and are not needed for verification claim.
     *
     * @return bool True if the claim is the Claims that have been verified and are not needed for verification, false otherwise.
     */
    public function isVerifiedClaims(): bool
    {
        return $this === self::VERIFIED_CLAIMS;
    }

    /**
     * Checks if the claim is the Place of birth claim.
     *
     * @return bool True if the claim is the Place of birth, false otherwise.
     */
    public function isPlaceOfBirth(): bool
    {
        return $this === self::PLACE_OF_BIRTH;
    }

    /**
     * Checks if the claim is the Nationalities or citizenships held claim.
     *
     * @return bool True if the claim is the Nationalities or citizenships held, false otherwise.
     */
    public function isNationalities(): bool
    {
        return $this === self::NATIONALITIES;
    }

    /**
     * Checks if the claim is the Family name at birth claim.
     *
     * @return bool True if the claim is the Family name at birth, false otherwise.
     */
    public function isBirthFamilyName(): bool
    {
        return $this === self::BIRTH_FAMILY_NAME;
    }

    /**
     * Checks if the claim is the Given name at birth claim.
     *
     * @return bool True if the claim is the Given name at birth, false otherwise.
     */
    public function isBirthGivenName(): bool
    {
        return $this === self::BIRTH_GIVEN_NAME;
    }

    /**
     * Checks if the claim is the Middle name at birth claim.
     *
     * @return bool True if the claim is the Middle name at birth, false otherwise.
     */
    public function isBirthMiddleName(): bool
    {
        return $this === self::BIRTH_MIDDLE_NAME;
    }

    /**
     * Checks if the claim is the Salutation claim.
     *
     * @return bool True if the claim is the Salutation, false otherwise.
     */
    public function isSalutation(): bool
    {
        return $this === self::SALUTATION;
    }

    /**
     * Checks if the claim is the Title claim.
     *
     * @return bool True if the claim is the Title, false otherwise.
     */
    public function isTitle(): bool
    {
        return $this === self::TITLE;
    }

    /**
     * Checks if the claim is the Mobile Subscriber Integrated Services Digital Network Number claim.
     *
     * @return bool True if the claim is the Mobile Subscriber Integrated Services Digital Network Number, false otherwise.
     */
    public function isMsisdn(): bool
    {
        return $this === self::MSISDN;
    }

    /**
     * Checks if the claim is the Any other names by which the End-User may be known claim.
     *
     * @return bool True if the claim is the Any other names by which the End-User may be known, false otherwise.
     */
    public function isAlsoKnownAs(): bool
    {
        return $this === self::ALSO_KNOWN_AS;
    }

    /**
     * Checks if the claim is the HTTP Transfer Method claim.
     *
     * @return bool True if the claim is the HTTP Transfer Method, false otherwise.
     */
    public function isHtm(): bool
    {
        return $this === self::HTM;
    }

    /**
     * Checks if the claim is the HTTP Transfer URI claim.
     *
     * @return bool True if the claim is the HTTP Transfer URI, false otherwise.
     */
    public function isHtu(): bool
    {
        return $this === self::HTU;
    }

    /**
     * Checks if the claim is the HTTP Authorization Header claim.
     *
     * @return bool True if the claim is the HTTP Authorization Header, false otherwise.
     */
    public function isAth(): bool
    {
        return $this === self::ATH;
    }

    /**
     * Checks if the claim is the HTTP Authentication Credential claim.
     *
     * @return bool True if the claim is the HTTP Authentication Credential, false otherwise.
     */
    public function isAtc(): bool
    {
        return $this === self::ATC;
    }

    /**
     * Checks if the claim is the Subscriber Identifier claim.
     *
     * @return bool True if the claim is the Subscriber Identifier, false otherwise.
     */
    public function isSubId(): bool
    {
        return $this === self::SUB_ID;
    }

    /**
     * Checks if the claim is the Required claims data claim.
     *
     * @return bool True if the claim is the Required claims data, false otherwise.
     */
    public function isRcd(): bool
    {
        return $this === self::RCD;
    }

    /**
     * Checks if the claim is the Required claims data interface claim.
     *
     * @return bool True if the claim is the Required claims data interface, false otherwise.
     */
    public function isRcdi(): bool
    {
        return $this === self::RCDI;
    }

    /**
     * Checks if the claim is the Credential Identifier claim.
     *
     * @return bool True if the claim is the Credential Identifier, false otherwise.
     */
    public function isCrn(): bool
    {
        return $this === self::CRN;
    }

    /**
     * Retrieves the claim value as a string.
     *
     * @return string The claim value. Basically the name of the registered claim
     */
    public function getActualName(): string
    {
        return $this->value;
    }
}
