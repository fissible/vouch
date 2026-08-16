Fissible\Vouch\Kernel\Assurance\AssuranceFacts (class)
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::$allPhishingResistant
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::$distinctCredentialCount
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::$hasMultiFactorCredential
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::$strongest
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::$weakestSatisfiedAt
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::__construct()
Fissible\Vouch\Kernel\Assurance\AssuranceFacts::fromFactors()
Fissible\Vouch\Kernel\Assurance\AssuranceLevel (class)
Fissible\Vouch\Kernel\Assurance\AssuranceLevel::$acr
Fissible\Vouch\Kernel\Assurance\AssuranceLevel::$facts
Fissible\Vouch\Kernel\Assurance\AssuranceLevel::__construct()
Fissible\Vouch\Kernel\Assurance\AssuranceLevel::satisfiesRecency()
Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary (interface)
Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::name()
Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary (class)
Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary::name()
Fissible\Vouch\Kernel\Attempt\AttemptState (enum)
Fissible\Vouch\Kernel\Attempt\AttemptState::$name
Fissible\Vouch\Kernel\Attempt\AttemptState::$value
Fissible\Vouch\Kernel\Attempt\AttemptState::Authenticated (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::FactorPending (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::FactorSatisfied (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::Failed (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::Identified (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::Initiated (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::Locked (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::RegistrationRequired (case)
Fissible\Vouch\Kernel\Attempt\AttemptState::cases()
Fissible\Vouch\Kernel\Attempt\AttemptState::from()
Fissible\Vouch\Kernel\Attempt\AttemptState::tryFrom()
Fissible\Vouch\Kernel\Attempt\TransitionRules (class)
Fissible\Vouch\Kernel\Attempt\TransitionRules::allows()
Fissible\Vouch\Kernel\Attempt\TransitionRules::isTerminal()
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture (enum)
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::$name
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::$value
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::Friendly (case)
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::Strict (case)
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::cases()
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::from()
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::isAtLeastAsStrictAs()
Fissible\Vouch\Kernel\Enumeration\EnumerationPosture::tryFrom()
Fissible\Vouch\Kernel\Enumeration\ErrorShaper (class)
Fissible\Vouch\Kernel\Enumeration\ErrorShaper::shape()
Fissible\Vouch\Kernel\Enumeration\Outcome (enum)
Fissible\Vouch\Kernel\Enumeration\Outcome::$name
Fissible\Vouch\Kernel\Enumeration\Outcome::$value
Fissible\Vouch\Kernel\Enumeration\Outcome::CredentialRejected (case)
Fissible\Vouch\Kernel\Enumeration\Outcome::IdentifierKnown (case)
Fissible\Vouch\Kernel\Enumeration\Outcome::IdentifierUnknown (case)
Fissible\Vouch\Kernel\Enumeration\Outcome::Locked (case)
Fissible\Vouch\Kernel\Enumeration\Outcome::cases()
Fissible\Vouch\Kernel\Enumeration\Outcome::from()
Fissible\Vouch\Kernel\Enumeration\Outcome::tryFrom()
Fissible\Vouch\Kernel\Factor\FactorKind (enum)
Fissible\Vouch\Kernel\Factor\FactorKind::$name
Fissible\Vouch\Kernel\Factor\FactorKind::$value
Fissible\Vouch\Kernel\Factor\FactorKind::Inherence (case)
Fissible\Vouch\Kernel\Factor\FactorKind::Knowledge (case)
Fissible\Vouch\Kernel\Factor\FactorKind::Possession (case)
Fissible\Vouch\Kernel\Factor\FactorKind::cases()
Fissible\Vouch\Kernel\Factor\FactorKind::from()
Fissible\Vouch\Kernel\Factor\FactorKind::tryFrom()
Fissible\Vouch\Kernel\Factor\FactorStrength (enum)
Fissible\Vouch\Kernel\Factor\FactorStrength::$name
Fissible\Vouch\Kernel\Factor\FactorStrength::$value
Fissible\Vouch\Kernel\Factor\FactorStrength::Knowledge (case)
Fissible\Vouch\Kernel\Factor\FactorStrength::Possession (case)
Fissible\Vouch\Kernel\Factor\FactorStrength::PossessionStrong (case)
Fissible\Vouch\Kernel\Factor\FactorStrength::PossessionWeak (case)
Fissible\Vouch\Kernel\Factor\FactorStrength::Recovery (case)
Fissible\Vouch\Kernel\Factor\FactorStrength::atLeast()
Fissible\Vouch\Kernel\Factor\FactorStrength::cases()
Fissible\Vouch\Kernel\Factor\FactorStrength::from()
Fissible\Vouch\Kernel\Factor\FactorStrength::tryFrom()
Fissible\Vouch\Kernel\Factor\SatisfiedFactor (class)
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$authenticatorId
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$credentialId
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$factorId
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$isMultiFactor
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$kind
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$phishingResistant
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$satisfiedAt
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$strength
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::$userVerified
Fissible\Vouch\Kernel\Factor\SatisfiedFactor::__construct()
Fissible\Vouch\Kernel\Policy\AllOf (class)
Fissible\Vouch\Kernel\Policy\AllOf::$requireDistinctCredentials
Fissible\Vouch\Kernel\Policy\AllOf::$requireIndependentAuthenticators
Fissible\Vouch\Kernel\Policy\AllOf::$requirements
Fissible\Vouch\Kernel\Policy\AllOf::__construct()
Fissible\Vouch\Kernel\Policy\AnyOf (class)
Fissible\Vouch\Kernel\Policy\AnyOf::$requirements
Fissible\Vouch\Kernel\Policy\AnyOf::__construct()
Fissible\Vouch\Kernel\Policy\FactorRequirement (class)
Fissible\Vouch\Kernel\Policy\FactorRequirement::$factorId
Fissible\Vouch\Kernel\Policy\FactorRequirement::$minimumStrength
Fissible\Vouch\Kernel\Policy\FactorRequirement::$phishingResistant
Fissible\Vouch\Kernel\Policy\FactorRequirement::$userVerified
Fissible\Vouch\Kernel\Policy\FactorRequirement::__construct()
Fissible\Vouch\Kernel\Policy\PolicyDocument (class)
Fissible\Vouch\Kernel\Policy\PolicyDocument::$posture
Fissible\Vouch\Kernel\Policy\PolicyDocument::$requirement
Fissible\Vouch\Kernel\Policy\PolicyDocument::__construct()
Fissible\Vouch\Kernel\Policy\PolicyParser (class)
Fissible\Vouch\Kernel\Policy\PolicyParser::parse()
Fissible\Vouch\Kernel\Policy\PolicyResolver (class)
Fissible\Vouch\Kernel\Policy\PolicyResolver::resolve()
Fissible\Vouch\Kernel\Policy\Requirement (interface)
Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator (class)
Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator::evaluate()
Fissible\Vouch\Kernel\Satisfiability\Verdict (class)
Fissible\Vouch\Kernel\Satisfiability\Verdict::$satisfied
Fissible\Vouch\Kernel\Satisfiability\Verdict::$usedFactors
Fissible\Vouch\Kernel\Satisfiability\Verdict::satisfiedBy()
Fissible\Vouch\Kernel\Satisfiability\Verdict::unsatisfied()
Fissible\Vouch\Kernel\Screen\AuthStep (enum)
Fissible\Vouch\Kernel\Screen\AuthStep::$name
Fissible\Vouch\Kernel\Screen\AuthStep::$value
Fissible\Vouch\Kernel\Screen\AuthStep::Challenge (case)
Fissible\Vouch\Kernel\Screen\AuthStep::Enroll (case)
Fissible\Vouch\Kernel\Screen\AuthStep::Identify (case)
Fissible\Vouch\Kernel\Screen\AuthStep::Recover (case)
Fissible\Vouch\Kernel\Screen\AuthStep::StepUp (case)
Fissible\Vouch\Kernel\Screen\AuthStep::cases()
Fissible\Vouch\Kernel\Screen\AuthStep::from()
Fissible\Vouch\Kernel\Screen\AuthStep::tryFrom()
Fissible\Vouch\Kernel\Screen\FactorOption (class)
Fissible\Vouch\Kernel\Screen\FactorOption::$factorId
Fissible\Vouch\Kernel\Screen\FactorOption::$isDefault
Fissible\Vouch\Kernel\Screen\FactorOption::$label
Fissible\Vouch\Kernel\Screen\FactorOption::$strength
Fissible\Vouch\Kernel\Screen\FactorOption::__construct()
Fissible\Vouch\Kernel\Screen\FieldSpec (class)
Fissible\Vouch\Kernel\Screen\FieldSpec::$autocomplete
Fissible\Vouch\Kernel\Screen\FieldSpec::$maxLength
Fissible\Vouch\Kernel\Screen\FieldSpec::$name
Fissible\Vouch\Kernel\Screen\FieldSpec::$type
Fissible\Vouch\Kernel\Screen\FieldSpec::__construct()
Fissible\Vouch\Kernel\Screen\RetryPolicy (class)
Fissible\Vouch\Kernel\Screen\RetryPolicy::$attemptsRemaining
Fissible\Vouch\Kernel\Screen\RetryPolicy::$lockedUntil
Fissible\Vouch\Kernel\Screen\RetryPolicy::$retryAfter
Fissible\Vouch\Kernel\Screen\RetryPolicy::__construct()
Fissible\Vouch\Kernel\Screen\ScreenSpec (class)
Fissible\Vouch\Kernel\Screen\ScreenSpec::$challengePayload
Fissible\Vouch\Kernel\Screen\ScreenSpec::$errors
Fissible\Vouch\Kernel\Screen\ScreenSpec::$fields
Fissible\Vouch\Kernel\Screen\ScreenSpec::$offeredFactors
Fissible\Vouch\Kernel\Screen\ScreenSpec::$retry
Fissible\Vouch\Kernel\Screen\ScreenSpec::$step
Fissible\Vouch\Kernel\Screen\ScreenSpec::__construct()
