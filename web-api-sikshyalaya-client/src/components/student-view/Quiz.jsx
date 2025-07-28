import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";

// List of study and quiz-related icons
const quizIcons = ["📖", "📝", "📚", "🔎", "❓", "✅", "🎓", "🏆", "💡", "📋", "✏️", "🧠", "🎯", "📜", "📊"];

const QuizList = () => {
  const [quizSets, setQuizSets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [quizIconsMap, setQuizIconsMap] = useState({});

  useEffect(() => {
    axios
      .get("http://localhost:8000/instructor/quiz")
      .then((response) => {
        if (response.data.success) {
          setQuizSets(response.data.data);

          // Assign random icons to each quiz
          const iconsMap = {};
          response.data.data.forEach((quiz) => {
            iconsMap[quiz._id] = quizIcons[Math.floor(Math.random() * quizIcons.length)];
          });
          setQuizIconsMap(iconsMap);
        } else {
          setError("Failed to fetch quizzes.");
        }
      })
      .catch((error) => {
        console.error("Error fetching quiz sets:", error);
        setError("Something went wrong. Please try again later.");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <p className="text-center text-gray-600 text-lg">Loading quizzes...</p>;
  }

  if (error) {
    return <p className="text-center text-red-500 text-lg">{error}</p>;
  }

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900 p-8">
      {quizSets.length === 0 ? (
        <p className="text-center text-gray-600 text-lg">No quiz sets available</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
          {quizSets.map((quiz) => (
            <Link to={`/quiz/${quiz._id}`} key={quiz._id}>
              <div className="bg-white shadow-md p-6 rounded-lg cursor-pointer hover:shadow-xl hover:bg-blue-50 transition duration-300 border border-gray-300 text-center transform hover:scale-105">
                
                {/* Title */}
                <h3 className="text-xl font-semibold text-gray-900 mb-2">{quiz.title}</h3>
                
                {/* Category with Random Study Icon */}
                <div className="flex justify-center items-center gap-2 mb-2">
                  <span className="text-lg">{quizIconsMap[quiz._id]}</span>
                  <span className="inline-block bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-xs font-semibold">
                    {quiz.category}
                  </span>
                </div>
                
                {/* Optional: New Quiz Badge */}
                {quiz.isNew && (
                  <span className="bg-green-500 text-white px-2 py-1 text-xs rounded-full">
                    New!
                  </span>
                )}

              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};

export default QuizList;
