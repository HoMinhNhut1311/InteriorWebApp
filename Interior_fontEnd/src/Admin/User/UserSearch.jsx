import { faMagnifyingGlass } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useEffect, useState } from "react";
import { getAllUserByContainingUsername, getUserGoogle } from "../../Data/User/userApi";
import { Link } from "react-router-dom";
import { RingLoader } from "react-spinners";

function UserSearch() {
    const [keyWord, setKeyWord] = useState('');
    const [data, setData] = useState([]);
    const [onLoad, setOnLoad] = useState(false);

    const handleKeyWord = (e) => {
        setKeyWord(e.target.value);
    };

    const handleGetUserGoogle = () => {
        getUserGoogle().then(res => setData(res));
    }

    const setDataByKeyWord = async () => {
        setOnLoad(true)
        const result = await getAllUserByContainingUsername(keyWord);
        setData(result);
        setOnLoad(false);
    };

    useEffect(() => {
        if (keyWord) {
            setDataByKeyWord();
        } else {
            setData([]);
        }
    }, [keyWord]);

    return (
        <div className="userEdit-container">
            <div className="keyWord-contain">
                {keyWord && (
                    <>
                        <span>Tìm kiếm kết quả cho: </span>
                        <span className="text-success">{keyWord}</span>
                    </>
                )}
            </div>
                <div className="user-oauth2 mb-3">
                <button className="btn btn-success" onClick={() => handleGetUserGoogle()}>Người dùng đăng nhập bằng Google</button>
                </div>

            {onLoad && <div className="my-loader-wrapper">
                <div className="my-loader">
                    <RingLoader color="#36d7b7" size={140} loading={onLoad} />
                </div>
            </div>}
            <div className="input-group mb-3 search-container">
                <input
                    type="text"
                    className="form-control myInput"
                    placeholder="Tìm kiếm tên Tài Khoản...."
                    aria-label="Recipient's username"
                    aria-describedby="basic-addon2"
                    value={keyWord}
                    onChange={handleKeyWord}
                />
                <span className="input-group-text mySearch" id="basic-addon2">
                    <FontAwesomeIcon icon={faMagnifyingGlass} />
                </span>
                {data.length > 0 && (
                    <div className="result-container row mt-5" style={{cursor : 'pointer'}}>
                        {data.map((user, index) => (
                            <Link key={index}  to={`/admin/user/detail/${user.userId}`}
                            className="col-12 d-flex justify-content-between p-2 text-center search-hover-result result-element">
                                <div className="fw-bold p-2 text-result">
                                    {user.userName ?? user.fullName}
                                </div>
                            </Link>
                        ))}
                    </div>
                )}
            </div>
        </div>
        
    );
}

export default UserSearch;
