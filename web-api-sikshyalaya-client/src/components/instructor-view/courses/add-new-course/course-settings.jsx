import MediaProgressbar from "@/components/media-progress-bar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InstructorContext } from "@/context/instructor-context";
import { mediaUploadService } from "@/services";
import { Upload, Trash2 } from "lucide-react";
import { useContext, useRef } from "react";

function CourseSettings() {
  const {
    courseLandingFormData,
    setCourseLandingFormData,
    mediaUploadProgress,
    setMediaUploadProgress,
    mediaUploadProgressPercentage,
    setMediaUploadProgressPercentage,
  } = useContext(InstructorContext);

  const fileInputRef = useRef(null);

  async function handleImageUploadChange(event) {
    const selectedImage = event.target.files[0];

    if (selectedImage) {
      const imageFormData = new FormData();
      imageFormData.append("file", selectedImage);

      try {
        setMediaUploadProgress(true);
        const response = await mediaUploadService(
          imageFormData,
          setMediaUploadProgressPercentage
        );
        if (response.success) {
          setCourseLandingFormData({
            ...courseLandingFormData,
            image: response.data.url,
          });
          setMediaUploadProgress(false);
        }
      } catch (e) {
        console.log(e);
      }
    }
  }

  return (
    <div className="p-8 min-h-screen bg-gradient-to-br from-white via-gray-100 to-gray-200 text-gray-900">
  <Card className="bg-white shadow-2xl p-6 rounded-xl">
    <CardHeader>
      <CardTitle className="text-gray-900 text-xl font-semibold tracking-wide">
        Course Thumbnail
      </CardTitle>
    </CardHeader>
    <div className="p-4">
      {mediaUploadProgress ? (
        <MediaProgressbar
          isMediaUploading={mediaUploadProgress}
          progress={mediaUploadProgressPercentage}
        />
      ) : null}
    </div>
    <CardContent>
      {courseLandingFormData?.image ? (
        <div className="flex flex-col items-center space-y-6">
          {/* Fixed Larger Image Size */}
          <div className="relative">
            <img
              src={courseLandingFormData.image}
              alt="Course Preview"
              className="rounded-lg shadow-xl border border-gray-300 w-[600px] h-[350px] object-cover"
            />
            {/* Improved "Remove Image" Button */}
            <button
              onClick={() =>
                setCourseLandingFormData({ ...courseLandingFormData, image: "" })
              }
              className="absolute top-2 right-2 flex items-center gap-1 px-3 py-1 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700 transition duration-300"
            >
              <Trash2 className="w-4 h-4" />
              Remove
            </button>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <Label className="text-gray-700 text-sm font-medium">Upload Course Image</Label>
          <input
            type="file"
            accept="image/*"
            onChange={handleImageUploadChange}
            ref={fileInputRef}
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center justify-center px-6 py-3 bg-blue-600 text-white border border-blue-500 rounded-lg hover:bg-blue-700 transition duration-300"
          >
            <Upload className="w-5 h-5 mr-2" />
            Select Image
          </button>
        </div>
      )}
    </CardContent>
  </Card>
</div>


  );
}

export default CourseSettings;
