package com.hominhnhut.WMN_BackEnd.service.impl;
import com.hominhnhut.WMN_BackEnd.domain.enity.Cart;
import com.hominhnhut.WMN_BackEnd.domain.enity.CartProduct;
import com.hominhnhut.WMN_BackEnd.domain.enity.Product;
import com.hominhnhut.WMN_BackEnd.domain.enity.User;
import com.hominhnhut.WMN_BackEnd.domain.request.CartRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.CartResponse;
import com.hominhnhut.WMN_BackEnd.exception.errorType;
import com.hominhnhut.WMN_BackEnd.exception.myException.AppException;
import com.hominhnhut.WMN_BackEnd.mapper.MyMapperInterFace;
import com.hominhnhut.WMN_BackEnd.repository.CartRepository;
import com.hominhnhut.WMN_BackEnd.repository.ProductRepository;
import com.hominhnhut.WMN_BackEnd.repository.UserRepository;
import com.hominhnhut.WMN_BackEnd.service.Interface.CartService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.stereotype.Service;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;
@Service
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
@RequiredArgsConstructor
public class CartServiceImpl implements CartService {
    CartRepository cartRepository;
    ProductRepository productRepository;
    UserRepository userRepository;
    MyMapperInterFace<CartRequest, Cart, CartResponse> mapper;
    @Override
    public List<CartResponse> getAllCart() {
        return this.cartRepository.findAll().stream()
                .map(this.mapper::mapToResponese).
                collect(Collectors.toList());
    }
    @Override
    public CartResponse findCartById(String id) {
        Cart cart = cartRepository.findById(id).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        return mapper.mapToResponese(cart);
    }
    @Override
    public CartResponse saveCart(CartRequest cartRequest) {
        Cart cart = mapper.mapFromRequest(cartRequest);
        Optional<User> user = userRepository.findUSerByUsername(cartRequest.getUsername());
        if (user.isEmpty()) {
            throw new AppException(errorType.NotFoundUsername);
        }
        cart.setUser(user.get());
        cart.setLocalDate(LocalDate.now());
        cart.setStatus(false);

        Set<CartProduct> cartProducts = new HashSet<>();
        for (String productId : cartRequest.getProductIds()) {
            boolean isExistProduct = false;
            Product product = productRepository.getProductByProductId(productId);
            if (product == null) {
                throw new AppException(errorType.notFoundProductName);
            }
            for(CartProduct cartProduct : cartProducts) {
                if (cartProduct.getProduct().getProductId().equals(productId)) {
                    cartProduct.setQuantity(cartProduct.getQuantity() + 1);
                    isExistProduct = true;
                }
            }

            if (!isExistProduct) {
                CartProduct cartProduct = new CartProduct();
                cartProduct.setCart(cart);
                cartProduct.setProduct(product);
                cartProduct.setQuantity(cartProduct.getQuantity());
                cartProducts.add(cartProduct);
            }

        }

        cart.setCartProducts(cartProducts);
        System.out.println(cart);
        return mapper.mapToResponese(cartRepository.saveAndFlush(cart));
    }
    @Override
    public CartResponse updateCart(CartRequest cartRequest, String id) {
        Cart cartExist = cartRepository.findById(id).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        cartExist.setLocalDate(cartRequest.getLocalDate());
        cartExist.setStatus(cartRequest.isStatus());
        Optional<User> user = userRepository.findUSerByUsername(cartRequest.getUsername());
        if (user.isEmpty()) {
            throw new AppException(errorType.notFoundRoleName);
        }
        cartExist.setUser(user.get());
        cartExist.getCartProducts().clear();
        Map<String, Integer> productQuantityMap = new HashMap<>();
        for (String productId : cartRequest.getProductIds()) {
            productQuantityMap.put(productId, productQuantityMap.getOrDefault(productId, 0) + 1);
        }
        for (String productId : productQuantityMap.keySet()) {
            Product product = productRepository.getProductByProductId(productId);
            if (product == null) {
                throw new AppException(errorType.notFoundRoleName);
            }
            CartProduct cartProduct = new CartProduct();
            cartProduct.setCart(cartExist);
            cartProduct.setProduct(product);
            cartProduct.setQuantity(productQuantityMap.get(productId));
            cartExist.getCartProducts().add(cartProduct);
        }
        Cart updatedCart = cartRepository.save(cartExist);
        return mapper.mapToResponese(updatedCart);
    }
    @Override
    public void deleteCart(String id) {
        Cart cartExist = cartRepository.findById(id).orElseThrow(
                () -> new AppException(errorType.notFound)
        );
        cartRepository.deleteById(id);
    }
}