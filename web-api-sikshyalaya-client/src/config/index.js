export const signUpFormControls = [
  {
    name: "fName",
    label: "User Name",
    placeholder: "Enter your user name",
    type: "text",
    componentType: "input",
  },
  {
    name: "email",
    label: "User Email",
    placeholder: "Enter your user email",
    type: "email",
    componentType: "input",
  },
  {
    name: "phone", // New phone field
    label: "Phone Number",
    type: "tel",
    placeholder: "Enter your phone number",
    componentType: "input",
  },
  {
    name: "password",
    label: "Password",
    placeholder: "Enter your password",
    type: "password",
    componentType: "input",
  },
];

export const signInFormControls = [
  {
    name: "email",
    label: "User Email",
    placeholder: "Enter your user email",
    type: "email",
    componentType: "input",
  },
  {
    name: "password",
    label: "Password",
    placeholder: "Enter your password",
    type: "password",
    componentType: "input",
  },
];

export const otpFormControls = [
  {
    name: "otp",
    label: "One-Time Password",
    placeholder: "Enter the 6-digit OTP",
    type: "text",
    componentType: "input",
  },
];

export const initialSignInFormData = {
  email: "",
  password: "",
};

export const initialSignUpFormData = {
  fName: "",
  email: "",
  password: "",
};

export const languageOptions = [
  { id: "english", label: "English" },
  { id: "nepali", label: "Nepali" },
];

export const courseLevelOptions = [
  { id: "under-secretary", label: "Under Secretary" },
  { id: "section-officer", label: "Section Officer" },
  { id: "nayab-subba", label: "Nayab Subba" },
  { id: "kharidar", label: "Kharidar" }
];

export const courseCategories = [
  { id: "health-services", label: "Health Services" },
  { id: "judicial-services", label: "Judicial Services" },
  { id: "engineering-services", label: "Engineering Services" },
  { id: "education-services", label: "Education Services" },
  { id: "administrative-services", label: "Administrative Services" },
  { id: "police-security-services", label: "Police and Security Services" },
  { id: "foreign-affairs-services", label: "Foreign Affairs Services" },
  { id: "miscellaneous-services", label: "Miscellaneous Services" }
];


export const courseLandingPageFormControls = [
  {
    name: "title",
    label: "Title",
    componentType: "input",
    type: "text",
    placeholder: "Enter course title",
  },
  {
    name: "category",
    label: "Category",
    componentType: "select",
    type: "text",
    placeholder: "",
    options: courseCategories,
  },
  {
    name: "level",
    label: "Level",
    componentType: "select",
    type: "text",
    placeholder: "",
    options: courseLevelOptions,
  },
  {
    name: "primaryLanguage",
    label: "Primary Language",
    componentType: "select",
    type: "text",
    placeholder: "",
    options: languageOptions,
  },
  {
    name: "subtitle",
    label: "Subtitle",
    componentType: "input",
    type: "text",
    placeholder: "Enter course subtitle",
  },
  {
    name: "description",
    label: "Description",
    componentType: "textarea",
    type: "text",
    placeholder: "Enter course description",
  },
  {
    name: "pricing",
    label: "Pricing",
    componentType: "input",
    type: "number",
    placeholder: "Enter course pricing",
  },
  {
    name: "objectives",
    label: "Objectives",
    componentType: "textarea",
    type: "text",
    placeholder: "Enter course objectives",
  },
  {
    name: "welcomeMessage",
    label: "Welcome Message",
    componentType: "textarea",
    placeholder: "Welcome message for students",
  },
];

export const courseLandingInitialFormData = {
  title: "",
  category: "",
  level: "",
  primaryLanguage: "",
  subtitle: "",
  description: "",
  pricing: "",
  objectives: "",
  welcomeMessage: "",
  image: "",
};

export const courseCurriculumInitialFormData = [
  {
    title: "",
    videoUrl: "",
    freePreview: false,
    public_id: "",
  },
];

export const sortOptions = [
  { id: "price-lowtohigh", label: "Price: Low to High" },
  { id: "price-hightolow", label: "Price: High to Low" },
  { id: "title-atoz", label: "Title: A to Z" },
  { id: "title-ztoa", label: "Title: Z to A" },
];

export const filterOptions = {
  category: courseCategories,
  level: courseLevelOptions,
  primaryLanguage: languageOptions,
};
