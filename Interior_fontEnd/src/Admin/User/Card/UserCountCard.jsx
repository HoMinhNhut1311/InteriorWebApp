import { useEffect, useState } from "react";

function UserCountCard({handleRole, roleData, setRoleData}) {

    const [countTotal, setCountTotal] = useState(0);

    // Hàm này sẽ trả về một class màu ngẫu nhiên từ Bootstrap
    const getRandomColorClass = () => {
        const colors = ['primary', 'secondary', 'success', 'warning', 'info', 'light'];
        const randomIndex = Math.floor(Math.random() * colors.length);
        return `${colors[randomIndex]}`;
    };


    useEffect(() => {
        const total = roleData.reduce((accumulator, currentValue) => accumulator + currentValue?.count, 0);
        setCountTotal(total);
    }, [roleData]);

    return (  
        <>
            {roleData.map((role, index) => (
                <div className="col-md-3 col-sm-6" key={index}>
                    <div className="card mb-0">
                        <button  className={`card-body btn mb-0 btn-outline-${getRandomColorClass()}`} onClick={() => handleRole(role.roleId)}>
                            <div className="d-flex align-items-end justify-content-between mb-2">
                                <div className="me-2">
                                    <svg className="svg-icon svg-icon-sm svg-icon-heavy text-gray-600 mb-2">
                                        <use xlinkHref="#survey-1"> </use>
                                    </svg>
                                    <p className="text-sm text-uppercase text-gray-600 lh-1 mb-0">
                                        {role?.roleName}
                                    </p>
                                </div>
                                <p className="text-xxl lh-1 mb-0 text-dash-color-3">{role?.count}</p>
                            </div>
                            <div className="progress" style={{ height: 3 }}>
                                <div
                                    className="progress-bar bg-dash-color-3"
                                    role="progressbar"
                                    style={{ width: ((role?.count / countTotal * 100) + "%") }}
                                />
                            </div>
                        </button>
                    </div>
                </div>
            ))}
        
            <div className="col-md-3 col-sm-6">
                <div className="card mb-0">
                    <button className="card-body btn btn-outline-success" onClick={() => handleRole(0)}>
                        <div className="d-flex align-items-end justify-content-between mb-2">
                            <div className="me-2">
                                <svg className="svg-icon svg-icon-sm svg-icon-heavy text-gray-600 mb-2">
                                    <use xlinkHref="#paper-stack-1"> </use>
                                </svg>
                                <p className="text-sm text-uppercase text-gray-600 lh-1 mb-0">
                                    Tất cả Chức Vụ
                                </p>
                            </div>
                            <p className="text-xxl lh-1 mb-0 text-dash-color-4">{countTotal}</p>
                        </div>
                        <div className="progress" style={{ height: 3 }}>
                            <div
                                className="progress-bar bg-dash-color-4"
                                role="progressbar"
                                style={{ width: '100%' }}
                            />
                        </div>
                    </button>
                </div>
            </div>
        </>
    );
}

export default UserCountCard;
