// src/components/common-form.jsx
import { Button } from "../ui/button";
import FormControls from "./form-controls";

function CommonForm({
  handleSubmit,
  buttonText,
  formControls = [],
  formData,
  setFormData,
  isButtonDisabled = false,
  customContent,
  onPasswordFocus,
}) {
  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <FormControls
        formControls={formControls}
        formData={formData}
        setFormData={setFormData}
        customContent={customContent}
        onPasswordFocus={onPasswordFocus}
      />
      <Button disabled={isButtonDisabled} type="submit" className="mt-5 w-full bg-blue-600 hover:bg-blue-700 text-white">
        {buttonText || "Submit"}
      </Button>
    </form>
  );
}

export default CommonForm;