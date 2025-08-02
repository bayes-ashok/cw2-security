import FormControls from "@/components/common-form/form-controls";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { courseLandingPageFormControls } from "@/config";
import { InstructorContext } from "@/context/instructor-context";
import { useContext } from "react";

function CourseLanding() {
  const { courseLandingFormData, setCourseLandingFormData } =
    useContext(InstructorContext);

  return (
    <div className="p-8 min-h-screen bg-gradient-to-br from-white via-gray-50 to-gray-200 text-gray-900">
  <Card className="bg-white shadow-2xl p-6 rounded-xl">
    <CardHeader>
      <CardTitle className="text-gray-900 text-xl font-semibold">
        Course Landing Page
      </CardTitle>
    </CardHeader>
    <CardContent>
      <FormControls
        formControls={courseLandingPageFormControls}
        formData={courseLandingFormData}
        setFormData={setCourseLandingFormData}
        className="space-y-6"
        inputClassName="w-full px-4 py-3 bg-white text-gray-900 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-600 outline-none placeholder-gray-500 transition duration-300"
        selectClassName="w-full px-4 py-3 bg-white text-gray-900 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-600 outline-none transition duration-300"
        textareaClassName="w-full px-4 py-3 bg-white text-gray-900 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-600 outline-none placeholder-gray-500 transition duration-300"
      />
    </CardContent>
  </Card>
</div>


  );
}

export default CourseLanding;
