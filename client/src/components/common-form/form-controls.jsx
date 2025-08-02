// src/components/form-controls.jsx
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { Textarea } from "../ui/textarea";

function FormControls({ formControls = [], formData, setFormData, customContent, onPasswordFocus }) {
  function renderComponentByType(getControlItem) {
    let element = null;
    const currentControlItemValue = formData[getControlItem.name] || "";

    switch (getControlItem.componentType) {
      case "input":
        element = (
          <Input
            id={getControlItem.name}
            name={getControlItem.name}
            placeholder={getControlItem.placeholder}
            type={getControlItem.type}
            value={currentControlItemValue}
            onChange={(event) =>
              setFormData({
                ...formData,
                [getControlItem.name]: event.target.value,
              })
            }
            onFocus={getControlItem.name === "password" ? onPasswordFocus : undefined}
            autoComplete={getControlItem.autocomplete}
            className="w-full px-4 py-3 bg-white text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none placeholder-gray-500 transition duration-300"
          />
        );
        break;
      case "select":
        element = (
          <Select
            onValueChange={(value) =>
              setFormData({
                ...formData,
                [getControlItem.name]: value,
              })
            }
            value={currentControlItemValue}
          >
            <SelectTrigger className="w-full bg-white text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 transition duration-300">
              <SelectValue placeholder={getControlItem.label} />
            </SelectTrigger>
            <SelectContent className="bg-white text-gray-900 border border-gray-300">
              {getControlItem.options && getControlItem.options.length > 0
                ? getControlItem.options.map((optionItem) => (
                    <SelectItem
                      key={optionItem.id}
                      value={optionItem.id}
                      className="hover:bg-gray-100"
                    >
                      {optionItem.label}
                    </SelectItem>
                  ))
                : null}
            </SelectContent>
          </Select>
        );
        break;
      case "textarea":
        element = (
          <Textarea
            id={getControlItem.name}
            name={getControlItem.name}
            placeholder={getControlItem.placeholder}
            value={currentControlItemValue}
            onChange={(event) =>
              setFormData({
                ...formData,
                [getControlItem.name]: event.target.value,
              })
            }
            className="w-full px-4 py-3 bg-white text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none placeholder-gray-500 transition duration-300"
          />
        );
        break;
      default:
        element = (
          <Input
            id={getControlItem.name}
            name={getControlItem.name}
            placeholder={getControlItem.placeholder}
            type={getControlItem.type}
            value={currentControlItemValue}
            onChange={(event) =>
              setFormData({
                ...formData,
                [getControlItem.name]: event.target.value,
              })
            }
            onFocus={getControlItem.name === "password" ? onPasswordFocus : undefined}
            autoComplete={getControlItem.autocomplete}
            className="w-full px-4 py-3 bg-white text-gray-900 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none placeholder-gray-500 transition duration-300"
          />
        );
        break;
    }

    return element;
  }

  return (
    <div className="flex flex-col gap-6">
      {formControls.map((controlItem) => (
        <div key={controlItem.name} className="space-y-2">
          <Label htmlFor={controlItem.name} className="text-gray-700 text-sm font-medium">
            {controlItem.label}
          </Label>
          {renderComponentByType(controlItem)}
          {controlItem.name === "password" && customContent}
        </div>
      ))}
    </div>
  );
}

export default FormControls;