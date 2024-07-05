package dev.webProject.VoluntHeart.DTOmapper;

import java.util.ArrayList;
import java.util.List;
import dev.webProject.VoluntHeart.DTO.UserDTO;
import dev.webProject.VoluntHeart.Models.Users.FundraiserModel;
import dev.webProject.VoluntHeart.Models.Users.UserModel;

public class UserDTOmapper {


    public static UserDTO mapToUserDTO(UserModel user){

        UserDTO userDTO = new UserDTO();

        userDTO.setUserId(user.getUserId());
        userDTO.setUserSecret(user.getUserSecret());
        userDTO.setEmail(user.getEmail());
        userDTO.setFullName(user.getFullName());
        userDTO.setAbout(user.getAbout());
        userDTO.setDonor(user.isDonor());
        userDTO.setProfilePic(user.getProfilePic());
        userDTO.setCoverImage(user.getCoverImage());
        userDTO.setGoogleLogin(user.isGoogleLogin());
        userDTO.setUserLocation(user.getUserLocation());
        userDTO.setWebsite(user.getWebsite());

     if (user instanceof FundraiserModel) {
        FundraiserModel fundraiser = (FundraiserModel) user;
        userDTO.setRegNumber(fundraiser.getRegNumber());
        
    }

        userDTO.setFollowers(toListUserDtos(user.getFollowers()));
        userDTO.setFollowing(toListUserDtos(user.getFollowings()));
        


        return userDTO;
    }

   public static List<UserDTO> toListUserDtos(List<UserModel> followers) {
       List<UserDTO> userDTOsList = new ArrayList<>();

       for(UserModel user:followers){
        UserDTO userDTO = new UserDTO();
        userDTO.setUserSecret(user.getUserSecret());
        userDTO.setUserId(user.getUserId());
        userDTO.setFullName(user.getFullName());
        userDTO.setProfilePic(user.getProfilePic());
        userDTO.setDonor(user.isDonor());
        userDTOsList.add(userDTO);
       }
       return userDTOsList;
    
}
}
