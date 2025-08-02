import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";

const QuizPlay = () => {
  const { quizSetId } = useParams();
  const navigate = useNavigate();
  const [questions, setQuestions] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState({});
  const [score, setScore] = useState(0);
  const [showResults, setShowResults] = useState(false);
  const [wrongAnswers, setWrongAnswers] = useState([]);
  const [reviewMode, setReviewMode] = useState(false);
  const [reviewIndex, setReviewIndex] = useState(0);
  const [timeLeft, setTimeLeft] = useState(60);
  const [timerRunning, setTimerRunning] = useState(true);

  useEffect(() => {
    axios
      .get(`http://localhost:8000/instructor/question/${quizSetId}`)
      .then((response) => {
        if (response.data.success) {
          setQuestions(response.data.data);
        }
      })
      .catch((error) => {
        console.error("Error fetching questions:", error);
      });
  }, [quizSetId]);

  // Timer logic (stops when quiz is submitted)
  useEffect(() => {
    if (timeLeft <= 0 && timerRunning) {
      handleSubmit(); // Auto-submit when time runs out
      return;
    }

    if (timerRunning) {
      const timer = setInterval(() => {
        setTimeLeft((prevTime) => prevTime - 1);
      }, 1000);

      return () => clearInterval(timer);
    }
  }, [timeLeft, timerRunning]);

  const handleAnswerSelect = (index) => {
    setSelectedAnswers((prev) => ({
      ...prev,
      [currentIndex]: index,
    }));
  };

  const handleNextQuestion = () => {
    if (selectedAnswers[currentIndex] === undefined) {
      return; // Prevent moving forward without an answer
    }

    if (currentIndex + 1 < questions.length) {
      setCurrentIndex(currentIndex + 1);
    } else {
      handleSubmit();
    }
  };

  const handlePreviousQuestion = () => {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    }
  };

  const handleSubmit = () => {
    setTimerRunning(false);
    setShowResults(true);

    let tempWrongAnswers = [];
    let tempScore = 0;

    questions.forEach((q, index) => {
      const selected = selectedAnswers[index];
      if (selected === q.correctAnswer) {
        tempScore++;
      } else {
        tempWrongAnswers.push({
          question: q.question,
          options: q.options,
          selectedIndex: selected,
          correctIndex: q.correctAnswer,
        });
      }
    });

    setScore(tempScore);
    setWrongAnswers(tempWrongAnswers);
  };

  const handleNextMistake = () => {
    if (reviewIndex + 1 < wrongAnswers.length) {
      setReviewIndex(reviewIndex + 1);
    } else {
      setReviewMode(false);
    }
  };

  if (questions.length === 0) {
    return <p className="text-center text-gray-500">Loading questions...</p>;
  }

  return (
    <div className="bg-gray-100 min-h-screen p-6 flex flex-col items-center">
      {/* Progress & Timer */}
      <div className="flex justify-between items-center w-full max-w-lg">
        <h2 className="text-xl font-semibold">
          Question {currentIndex + 1} of {questions.length}
        </h2>
        {!showResults && (
          <p className="text-xl font-semibold text-red-600">
            ⏳ {Math.floor(timeLeft / 60)}:{(timeLeft % 60).toString().padStart(2, "0")}
          </p>
        )}
      </div>

      {/* Quiz Mode */}
      {!showResults && !reviewMode && (
        <div className="bg-white shadow-lg p-6 rounded-lg w-full max-w-lg mt-4">
          <h3 className="text-xl font-semibold mb-4">{questions[currentIndex].question}</h3>
          <div className="space-y-2">
            {questions[currentIndex].options.map((option, index) => (
              <button
                key={index}
                className={`block w-full text-left p-3 border rounded-lg ${
                  selectedAnswers[currentIndex] === index
                    ? "bg-blue-500 text-white"
                    : "bg-gray-200 hover:bg-gray-300"
                }`}
                onClick={() => handleAnswerSelect(index)}
              >
                {option}
              </button>
            ))}
          </div>

          <div className="flex justify-between mt-4">
            <button
              className="bg-gray-500 hover:bg-gray-600 text-white px-6 py-2 rounded"
              onClick={handlePreviousQuestion}
              disabled={currentIndex === 0}
            >
              Previous
            </button>

            <button
              className="bg-green-500 hover:bg-green-600 text-white px-6 py-2 rounded"
              onClick={handleNextQuestion}
              disabled={selectedAnswers[currentIndex] === undefined}
            >
              {currentIndex + 1 === questions.length ? "Finish Quiz" : "Next"}
            </button>
          </div>
        </div>
      )}

      {/* Show Final Score */}
      {showResults && !reviewMode && (
        <div className="text-center">
          <h3 className="text-3xl font-semibold">Quiz Completed!</h3>
          <p className="text-lg mt-3">
            Your Score: <span className="font-bold">{score} / {questions.length}</span>
          </p>

          {wrongAnswers.length > 0 ? (
            <button
              className="mt-6 bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded"
              onClick={() => {
                setReviewMode(true);
                setReviewIndex(0);
              }}
            >
              Review Mistakes
            </button>
          ) : (
            <button
              className="mt-6 bg-gray-700 hover:bg-gray-800 text-white px-6 py-2 rounded"
              onClick={() => navigate("/")}
            >
              Back to Quiz List
            </button>
          )}
        </div>
      )}

      {/* Review Mode */}
      {reviewMode && (
        <div className="bg-white shadow-lg p-6 rounded-lg w-full max-w-lg">
          <h3 className="text-xl font-semibold text-red-600 mb-4">Review Mistakes</h3>
          <p className="font-semibold text-lg">{wrongAnswers[reviewIndex].question}</p>

          <div className="mt-4 space-y-3">
            {wrongAnswers[reviewIndex].options.map((option, i) => (
              <div
                key={i}
                className={`flex justify-between items-center p-4 rounded-lg text-lg font-semibold border-2 ${
                  i === wrongAnswers[reviewIndex].correctIndex
                    ? "bg-green-500 text-white border-green-700"
                    : i === wrongAnswers[reviewIndex].selectedIndex
                    ? "bg-red-500 text-white border-black"
                    : "bg-gray-300 text-gray-800 border-gray-400"
                }`}
              >
                <span>{option}</span>
                {i === wrongAnswers[reviewIndex].correctIndex ? (
                  <span className="text-xl font-bold">✅</span>
                ) : i === wrongAnswers[reviewIndex].selectedIndex ? (
                  <span className="text-xl font-bold text-black">❎</span>
                ) : null}
              </div>
            ))}
          </div>

          <button
            className="mt-6 bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded w-full"
            onClick={handleNextMistake}
          >
            {reviewIndex + 1 === wrongAnswers.length ? "Finish Review" : "Next Mistake"}
          </button>
        </div>
      )}
    </div>
  );
};

export default QuizPlay;
