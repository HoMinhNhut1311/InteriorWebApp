
function ProductSearch({keyWord,setKeyWord}) {    
    const handleKeyWord = (e) => {
        setKeyWord(e.target.value);
    };

   

    return (
        <div className="userEdit-container">
            <div className="keyWord-contain mb-2">
                {keyWord && (
                    <>
                        <span>Tìm kiếm kết quả cho: </span>
                        <span className="text-success">{keyWord}</span>
                    </>
                )}
            </div>
            <div className="input-group mb-3 search-container">
                <input
                    type="text"
                    className="form-control myInput"
                    placeholder="Tìm kiếm tên Sản phẩm...."
                    aria-label="Recipient's product"
                    aria-describedby="basic-addon2"
                    value={keyWord}
                    onChange={handleKeyWord}
                />
            </div>
        </div>
        
    );
}

export default ProductSearch;
