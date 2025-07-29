import React, { useState, useEffect } from 'react';
import axios from 'axios';
import toast, { Toaster } from 'react-hot-toast';

const UpdateProfile = () => {
  const [formData, setFormData] = useState({
    fName: '',
    phone: '',
    password: '',
    currentPassword: '',
    twoFactorEnabled: false,
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  const axiosConfig = {
    baseURL: 'https://localhost:443',
    headers: {
      Authorization: `Bearer ${JSON.parse(sessionStorage.getItem('accessToken')) || ''}`
    }
  };

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await axios.get('/auth/getDetails', axiosConfig);
        setFormData({
          fName: response.data.user.fName || '',
          phone: response.data.user.phone || '',
          password: '',
          currentPassword: '',
          twoFactorEnabled: response.data.user.twoFactorEnabled || false,
        });
      } catch (error) {
        toast.error('Failed to load user data');
      }
    };
    fetchUserData();
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({ ...prev, [name]: type === 'checkbox' ? checked : value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    if (!formData.currentPassword) {
      newErrors.currentPassword = 'Current password is required';
    }
    if (formData.password && formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters long';
    }
    if (formData.fName && formData.fName.length < 2) {
      newErrors.fName = 'First name must be at least 2 characters long';
    }
    if (formData.phone && !/^\+?[\d\s-]{10,}$/.test(formData.phone)) {
      newErrors.phone = 'Please provide a valid phone number';
    }
    return newErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    const validationErrors = validateForm();

    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      setLoading(false);
      return;
    }

    try {
      const payload = {};
      if (formData.fName) payload.fName = formData.fName;
      if (formData.phone) payload.phone = formData.phone;
      if (formData.password) payload.password = formData.password;
      payload.currentPassword = formData.currentPassword;
      payload.twoFactorEnabled = formData.twoFactorEnabled;

      const response = await axios.put('/auth/update', payload, axiosConfig);
      
      toast.success(response.data.message);
      setFormData(prev => ({
        ...prev,
        password: '',
        currentPassword: '',
      }));
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Failed to update profile';
      toast.error(errorMessage);
      if (error.response?.data?.errors) {
        setErrors(error.response.data.errors.reduce((acc, err) => ({
          ...acc,
          [err.param]: err.msg
        }), {}));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-xl shadow-lg p-8">
        <Toaster position="top-center" />
        <h2 className="text-3xl font-bold mb-8 text-center text-gray-800">Update Profile</h2>
        <div className="flex flex-col gap-6">
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">First Name</label>
            <input
              type="text"
              name="fName"
              value={formData.fName}
              onChange={handleChange}
              className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
              placeholder="Enter first name"
            />
            {errors.fName && <p className="text-red-500 text-sm mt-1">{errors.fName}</p>}
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">Phone Number</label>
            <input
              type="tel"
              name="phone"
              value={formData.phone}
              onChange={handleChange}
              className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
              placeholder="Enter phone number"
            />
            {errors.phone && <p className="text-red-500 text-sm mt-1">{errors.phone}</p>}
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">New Password</label>
            <input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
              placeholder="Enter new password"
            />
            {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password}</p>}
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">Current Password</label>
            <input
              type="password"
              name="currentPassword"
              value={formData.currentPassword}
              onChange={handleChange}
              className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
              placeholder="Enter current password"
            />
            {errors.currentPassword && <p className="text-red-500 text-sm mt-1">{errors.currentPassword}</p>}
          </div>

          <div className="mb-6">
            <label className="flex items-center text-sm font-medium text-gray-700">
              <input
                type="checkbox"
                name="twoFactorEnabled"
                checked={formData.twoFactorEnabled}
                onChange={handleChange}
                className="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              Enable Two-Factor Authentication (OTP via Email)
            </label>
            {formData.twoFactorEnabled && (
              <p className="text-sm text-gray-600 mt-2">
                When enabled, an OTP will be sent to your email during login for added security.
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={handleSubmit}
            disabled={loading}
            className={`w-full p-3 rounded-lg text-white font-medium transition duration-200 ${
              loading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
            }`}
          >
            {loading ? 'Updating...' : 'Update Profile'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default UpdateProfile;