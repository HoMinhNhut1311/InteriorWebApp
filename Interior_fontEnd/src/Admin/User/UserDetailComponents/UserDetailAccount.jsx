import { useEffect, useState } from "react";
import { validateUser } from '../../../Data/User/ValidateUser'
import {UpdateUser} from '../../../Data/User/userApi'
import Swal from "sweetalert2";

// Chứa Username và Password
function UserDetailAccount({ userId,username, password, roleNames, setDetailAccount }) {
    const [account, setAccount] = useState({
        userId : '',
        username: '',
        password: '',
        roleNames : []
    });
    const [deniedChange, setDeniedChange] = useState(true);
    const [isChange, setIsChange] = useState(false);

    const [errorUsername, setErrorUsername] = useState('')
    const [errorPassword, setErrorPassword] = useState('')
    const [errorRole, setErrorRole] = useState('')

    const [onLoad, setOnLoad] = useState(false);

    // Update Data khi mới vào
    useEffect(() => {
        setAccount({
            username: username,
            password: password,
            roleNames : roleNames,
            userId : userId
        });
        
    }, [username]);

    useEffect(() => {
        if (username !== account.username || password !== account.password) {
            setIsChange(true);
        } else {
            setIsChange(false);
        }

        validateUser(account,setErrorUsername,setErrorPassword,setErrorRole,setIsChange);

    }, [account.username, account.password,account.roleNames]);

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setAccount({
            ...account,
            [name]: value
        });
    };
    const handleRole = (role) => {
        // Nếu role tồn tại thì gỡ
        const isChecked = account.roleNames.includes(role);
        if (isChecked) {
                // Gỡ 
                const newRole = account.roleNames.filter(r => r != role );
                setAccount({
                    ...account,
                    roleNames : newRole
                })
        }
        else {
        setAccount({
            ...account,
            roleNames : [...roleNames,role]
        })
    }
    }

    const updateUser = () => {
        console.log(account.roleNames);
        setOnLoad(true);
        UpdateUser(
            account.userId,account.username,account.password,account.roleNames
        ).then(res => {
            Swal.fire({
                title: 'Update thành công',
                text: `Username : ${res.userName} + '\n'
                        Password : ${res.password} + '\n'
                        RoleNames : ${res.roleNames}`,
                icon: "success",
              }).then(() => {
                setDetailAccount(account)
                setIsChange(false)
              }
              );
        }).finally(() => {
            setOnLoad(false);
        })
    }


    return (
        <>
            <h2 className="text-center text-primary">{deniedChange ? 'Xem thông tin' : 'Chỉnh sửa thông tin'}</h2>
            <div className="form-group">
                <label className="form-label fw-bold fs-5 text-green-yellow" htmlFor="username">Tài khoản</label>
                <input
                    type="text"
                    className={deniedChange ? "form-control disable" : 'form-control'}
                    id="username"
                    name="username"
                    value={account.username}
                    readOnly={deniedChange}
                    onChange={handleInputChange}
                />
                <span className="error-message text-danger">{errorUsername}</span>
            </div>

            <div className="form-group">
                <label className="form-label fw-bold fs-5 text-green-yellow" htmlFor="password">Mật khẩu</label>
                <input
                    type="text"
                    className={deniedChange ? "form-control disable" : 'form-control'}
                    id="password"
                    name="password"
                    value={account.password}
                    readOnly={deniedChange}
                    onChange={handleInputChange}
                />
                <span className="error-message text-danger">{errorPassword}</span>
            </div>

            <div className="form-group mt-2">
                    {/* <div className="form-check form-check-inline">
                        <input
                            className="form-check-input"
                            type="checkbox"
                            defaultValue=""
                            id="flexCheckChecked"
                            checked={account.roleNames.includes('Staff')}
                            onChange={() => handleRole('Staff')}
                            disabled={deniedChange}
                        />
                        <label className="form-check-label" htmlFor="flexCheckChecked">
                            User
                        </label>
                    </div> */}
                    <div>
                    <span className="text-danger">{errorRole}</span>
                    </div>
            </div>

            <div className="d-flex justify-content-end mt-3">
                {isChange 
                ? <button className="btn btn-primary me-3" onClick={() => updateUser()}>Cập nhật</button>
                    : <button className="btn btn-warning me-3">Chưa đủ điều kiện cập nhật</button>
            }
            
            
                <button className="btn btn-success" onClick={() => setDeniedChange(!deniedChange)}>
                    {deniedChange ? "Thay đổi" : "Chỉ đọc"}
                </button>
            </div>
        </>
    );
}

export default UserDetailAccount;
