import { createContext, useState } from 'react';

const CartContext = createContext();

const CartProvider = ({ children }) => {
  const [cart, setCart] = useState([]);

  const addToCart = (product,quantity) => {
    setCart((prevCart) => [...prevCart, { ...product, quantity: quantity }]);
  };

  const removeFromCart = (productId) => {
    setCart(cart.filter((item) => item.productId !== productId));
  };

  const updateQuantity = (product, quantity) => {
    setCart((prevCart) =>
      prevCart.map((item) =>
        item.productId === product.productId ? { ...item, quantity } : item
      )
    );
  };
  return (
    <CartContext.Provider
      value={{ cart, addToCart, removeFromCart, updateQuantity,setCart }}
    >
      {children}
    </CartContext.Provider>
  );
};

export { CartContext, CartProvider };
