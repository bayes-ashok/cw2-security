import React, { useState } from "react";
import axios from "axios";
import { useForm, useFieldArray } from "react-hook-form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { motion } from "framer-motion";
import { Trash2, PlusCircle } from "lucide-react";
import { Label } from "@/components/ui/label";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const AdminQuizPanel = () => {
  const [quizSetId, setQuizSetId] = useState(null);
  const { register, handleSubmit, control, reset } = useForm({
    defaultValues: {
      title: "",
      category: "",
      description: "",
      questions: [
        { question: "", options: ["", "", "", ""], correctAnswer: 0 },
      ],
    },
  });

  const { fields, append, remove } = useFieldArray({
    control,
    name: "questions",
  });

  const createQuizSet = async (data) => {
    try {
      const response = await axios.post(
        "http://localhost:8000/instructor/quiz/create",
        data
      );
      setQuizSetId(response.data.data._id);
    } catch (error) {
      console.error("Error creating quiz set", error);
    }
  };

  const addQuestions = async (data) => {
    try {
      await axios.post("http://localhost:8000/instructor/question/add", {
        quizSetId,
        questions: data.questions,
      });
      toast.success("Quiz created successfully! 🎉", { position: "top-right" });
      reset();
      setQuizSetId(null);
    } catch (error) {
      console.error("Error adding questions", error);
    }
  };

  return (
     
    <div className="">
     <ToastContainer />
      {!quizSetId ? (
        <Card className="p-8 shadow-lg rounded-2xl bg-white">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">
            Create Quiz Set
          </h2>
          <form onSubmit={handleSubmit(createQuizSet)} className="space-y-6">
            <div className="space-y-2">
              <Label className="text-gray-700">Quiz Title</Label>
              <Input
                {...register("title", { required: true })}
                placeholder="Enter quiz title"
                className="bg-gray-100 text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-gray-700">Category</Label>
              <Input
                {...register("category", { required: true })}
                placeholder="Enter category"
                className="bg-gray-100 text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-gray-700">Description</Label>
              <Textarea
                {...register("description", { required: true })}
                placeholder="Enter description"
                className="bg-gray-100 text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
              />
            </div>
            <Button
              type="submit"
              className="w-full bg-indigo-600 hover:bg-indigo-700 transition rounded-lg"
            >
              Create Quiz Set
            </Button>
          </form>
        </Card>
      ) : (
        <Card className="p-8 shadow-lg rounded-2xl bg-white">
          <h2 className="text-2xl font-semibold text-gray-900 mb-4">
            Add Questions
          </h2>
          <form onSubmit={handleSubmit(addQuestions)} className="space-y-6">
            {fields.map((item, index) => (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="p-6 border rounded-xl shadow-sm space-y-4 bg-gray-50 border-gray-300"
              >
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-medium text-gray-800">
                    Question {index + 1}
                  </h3>
                  <Button
                    type="button"
                    onClick={() => remove(index)}
                    className="bg-red-600 hover:bg-red-700 text-white p-2 rounded-lg"
                  >
                    <Trash2 size={18} />
                  </Button>
                </div>
                <Input
                  {...register(`questions.${index}.question`, {
                    required: true,
                  })}
                  placeholder="Enter question"
                  className="bg-gray-100 text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
                />
                <div className="grid grid-cols-2 gap-4">
                  {item.options.map((_, optIndex) => (
                    <Input
                      key={optIndex}
                      {...register(`questions.${index}.options.${optIndex}`, {
                        required: true,
                      })}
                      placeholder={`Option ${optIndex + 1}`}
                      className="bg-gray-100 text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
                    />
                  ))}
                </div>
                <div className="space-y-2">
                  <Label className="text-gray-700">
                    Correct Answer (Index 0-3)
                  </Label>
                  <Input
                    {...register(`questions.${index}.correctAnswer`, {
                      required: true,
                    })}
                    type="number"
                    min="0"
                    max="3"
                    className="bg-gray-100 text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
                  />
                </div>
              </motion.div>
            ))}
            <Button
              type="button"
              className="flex items-center gap-2 bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded-lg transition"
              onClick={() =>
                append({
                  question: "",
                  options: ["", "", "", ""],
                  correctAnswer: 0,
                })
              }
            >
              <PlusCircle size={18} />
              Add Question
            </Button>
            <Button
              type="submit"
              className="w-full bg-black hover:bg-gray-900 transition rounded-lg"
            >
              Submit Questions
            </Button>
          </form>
        </Card>
      )}
    </div>
  );
};

export default AdminQuizPanel;
