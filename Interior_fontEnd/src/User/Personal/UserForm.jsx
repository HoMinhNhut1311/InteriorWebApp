import { useContext, useEffect, useState } from "react";
import Swal from "sweetalert2";
import UserContext from "../../Context/userContext";
import {
  selectById,
  UpdateProfile,
  UploadImageProFile,
} from "../../Data/User/userApi.js";
import { parseJwt } from "../../Utils/Jwt.js";
import { RingLoader } from "react-spinners";

function UserForm() {
  const { token } = useContext(UserContext);
  const [selectedFile, setSelectedFile] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [user, setUser] = useState({});
  const userId = parseJwt(token).userId;
  const [profileId, setProfileId] = useState("");
  const [onLoad, setOnLoad] = useState(false);
  useEffect(() => {
    selectById(userId).then((res) => {
      setUser(res);
      setProfileId(res.profileId);
    });
  }, []);
  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      const validImageTypes = ["image/jpeg", "image/png", "image/gif"];
      if (validImageTypes.includes(file.type)) {
        setSelectedFile(file);
        setErrorMessage("");
      } else {
        setSelectedFile(null);
        setErrorMessage("Please select a valid image file (jpeg, png, gif)");
      }
      if (errorMessage) {
        Swal.fire({
          icon: "error",
          title: "Validation Error",
          text: errorMessage,
        });
      }
    }
  };
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    if (name === "dob") {
      setUser({
        ...user,
        birth: value,
      });
    } else {
      setUser({
        ...user,
        [name]: value,
      });
    }
  };

  const handleDeleteFile = () => {
    setSelectedFile(null);
    setErrorMessage("");
  };

  const handleRadioChange = (e) => {
    const { id, value } = e.target;
    setUser({
      ...user,
      sex: value === "true",
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setOnLoad(true);
    console.log(user.fullName);
    console.log(profileId);
    if (selectedFile === null) {
      return Swal.fire({
        title: "Vui lòng chọn file trước khi cập nhật",
        icon: "question",
      });
    } else {
      const fd = new FormData();
      fd.append("image", selectedFile);
      await UploadImageProFile(user.profileId, fd);
    }
    setOnLoad(false)
    await UpdateProfile(
      profileId,
      user.fullName,
      user.sex,
      user.birth,
      user.email,
      user.phone,
      user.userId
    )
      .then((res) => {
        Swal.fire({
          title: "Cập nhật thành công!",
          text: `Thành công`,
          icon: "success",
        }).then(() => {
          setUser({});
        });
      })
      .catch((error) => {
        console.error("Error updating profile:", error);
        Swal.fire({
          title: "Cập nhật thất bại!",
          text: `Lỗi `,
          icon: "error",
        });
      });
  };

  return (
    <div className="formbold-main-wrapper">
      {onLoad && (
        <div className="my-loader-wrapper">
          <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} loading={onLoad} />
          </div>
        </div>
      )}
      <div
        className="formbold-form-container d-flex border border-2"
        style={{ borderRadius: "15px" }}
      >
        <div className="containerr">
          <div className="headerr">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <g id="SVGRepo_bgCarrier" strokeWidth={0} />
              <g
                id="SVGRepo_tracerCarrier"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <g id="SVGRepo_iconCarrier">
                <path
                  d="M7 10V9C7 6.23858 9.23858 4 12 4C14.7614 4 17 6.23858 17 9V10C19.2091 10 21 11.7909 21 14C21 15.4806 20.1956 16.8084 19 17.5M7 10C4.79086 10 3 11.7909 3 14C3 15.4806 3.8044 16.8084 5 17.5M7 10C7.43285 10 7.84965 10.0688 8.24006 10.1959M12 12V21M12 12L15 15M12 12L9 15"
                  stroke="#000000"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />{" "}
              </g>
            </svg>{" "}
            <p>Chọn file ảnh để tải lên!</p>
          </div>
          <label htmlFor="filer" className="footerr">
            <svg
              fill="#000000"
              viewBox="0 0 32 32"
              xmlns="http://www.w3.org/2000/svg"
            >
              <g id="SVGRepo_bgCarrier" strokeWidth={0} />
              <g
                id="SVGRepo_tracerCarrier"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <g id="SVGRepo_iconCarrier">
                <path d="M15.331 6H8.5v20h15V14.154h-8.169z" />
                <path d="M18.153 6h-.009v5.342H23.5v-.002z" />
              </g>
            </svg>
            <p>{selectedFile ? selectedFile.name : "Not selected file"}</p>
            <svg
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              onClick={handleDeleteFile}
            >
              <g id="SVGRepo_bgCarrier" strokeWidth={0} />
              <g
                id="SVGRepo_tracerCarrier"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <g id="SVGRepo_iconCarrier">
                <path
                  d="M5.16565 10.1534C5.07629 8.99181 5.99473 8 7.15975 8H16.8402C18.0053 8 18.9237 8.9918 18.8344 10.1534L18.142 19.1534C18.0619 20.1954 17.193 21 16.1479 21H7.85206C6.80699 21 5.93811 20.1954 5.85795 19.1534L5.16565 10.1534Z"
                  stroke="#000000"
                  strokeWidth={2}
                />{" "}
                <path
                  d="M19.5 5H4.5"
                  stroke="#000000"
                  strokeWidth={2}
                  strokeLinecap="round"
                />{" "}
                <path
                  d="M10 3C10 2.44772 10.4477 2 11 2H13C13.5523 2 14 2.44772 14 3V5H10V3Z"
                  stroke="#000000"
                  strokeWidth={2}
                />{" "}
              </g>
            </svg>
          </label>
          <input id="filer" type="file" onChange={handleFileChange} />
          {errorMessage && <p className="error text-danger">{errorMessage}</p>}
        </div>
        <div className="formbold-form-wrapper ">
          <form>
            <div className="formbold-form-title">
              <h2>Thông tin cá nhân</h2>
            </div>
            <div className="formbold-input-flex">
              <div>
                <label htmlFor="fullName" className="formbold-form-label">
                  Họ và tên
                </label>
                <input
                  type="text"
                  name="fullName"
                  id="fullName"
                  className="formbold-form-input"
                  value={user.fullName}
                  onChange={handleInputChange}
                />
              </div>
              <div>
                <label htmlFor="dob" className="formbold-form-label">
                  Ngày sinh
                </label>
                <input
                  type="date"
                  name="dob"
                  id="dob"
                  className="formbold-form-input"
                  style={{ width: "100%" }}
                  value={user.birth}
                  onChange={handleInputChange}
                />
              </div>
            </div>
            <div className="formbold-input-flex">
              <div>
                <label htmlFor="email" className="formbold-form-label">
                  Email
                </label>
                <input
                  type="email"
                  name="email"
                  id="email"
                  className="formbold-form-input"
                  value={user.email}
                  onChange={handleInputChange}
                />
              </div>
              <div>
                <label htmlFor="phone" className="formbold-form-label">
                  Phone number
                </label>
                <input
                  type="text"
                  name="phone"
                  id="phone"
                  className="formbold-form-input"
                  value={user.phone}
                  onChange={handleInputChange}
                />
              </div>
            </div>{" "}
            <div className="formbold-input-flex">
              <label className="radio-button">
                <input
                  type="radio"
                  name="sex"
                  id="male"
                  value="true"
                  checked={user.sex === true}
                  onChange={handleRadioChange}
                />
                <span className="radio"></span>
                <label htmlFor="nam" className="formbold-form-label">
                  Nam
                </label>
              </label>

              <label className="radio-button">
                <input
                  type="radio"
                  name="sex"
                  id="female"
                  value="false"
                  checked={user.sex === false}
                  onChange={handleRadioChange}
                />
                <span className="radio"></span>
                <label htmlFor="nu" className="formbold-form-label">
                  Nữ
                </label>
              </label>
            </div>
            <button className="formbold-btn" onClick={handleSubmit}>
              Cập nhật thông tin
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default UserForm;
